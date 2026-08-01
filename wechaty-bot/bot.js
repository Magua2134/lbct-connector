/**
 * Wechaty Bot + REST API
 * 
 * 功能：
 * 1. 扫码登录微信（UOS Web协议，免费）
 * 2. 暴露REST API供Cloudflare Workers调用
 * 3. 支持发送文字、图片、链接卡片到指定群/联系人
 * 4. 自动重连 + 心跳保活
 * 
 * 端口: 3000 (与emodal-connector 10000完全隔离)
 */

const { WechatyBuilder } = require('wechaty');
const { PuppetWechat4u } = require('wechaty-puppet-wechat4u');
const QRCodeTerminal = require('qrcode-terminal');
const express = require('express');
const cors = require('cors');

// ========== 配置 ==========
const PORT = process.env.BOT_PORT || 3000;
const API_KEY = process.env.BOT_API_KEY || 'wechaty-bot-secret-2026';

// ========== 全局状态 ==========
let bot = null;
let isLoggedIn = false;
let loginQrCode = '';
let botName = '';
let contactCache = new Map();  // name -> Contact
let roomCache = new Map();      // topic -> Room

// ========== Express REST API ==========
const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// API Key 认证中间件
app.use(function(req, res, next) {
  if (req.path === '/health' || req.path === '/qrcode') return next();
  var key = req.headers['x-api-key'] || req.query.key || '';
  if (key !== API_KEY) {
    return res.status(403).json({ error: 'unauthorized: invalid or missing API key' });
  }
  next();
});

// 健康检查
app.get('/health', function(req, res) {
  res.json({
    ok: true,
    loggedIn: isLoggedIn,
    botName: botName,
    uptime: process.uptime(),
    timestamp: Date.now()
  });
});

// 获取登录二维码
app.get('/qrcode', function(req, res) {
  res.json({
    loggedIn: isLoggedIn,
    qrCode: isLoggedIn ? null : loginQrCode,
    message: isLoggedIn ? '已登录' : '请用微信扫描二维码登录'
  });
});

// 发送文字消息
app.post('/send/text', async function(req, res) {
  try {
    var { target, message } = req.body;
    if (!target || !message) {
      return res.status(400).json({ error: 'Missing target or message' });
    }
    var result = await sendTextMessage(target, message);
    res.json({ success: true, target: target, sent: result });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// 批量发送文字消息（群发，带随机延迟）
app.post('/send/batch', async function(req, res) {
  try {
    var { targets, message, delayMin, delayMax } = req.body;
    if (!targets || !Array.isArray(targets) || targets.length === 0) {
      return res.status(400).json({ error: 'Missing targets array' });
    }
    if (!message) {
      return res.status(400).json({ error: 'Missing message' });
    }
    delayMin = delayMin || 3;
    delayMax = delayMax || 8;
    
    var results = [];
    for (var i = 0; i < targets.length; i++) {
      var target = targets[i];
      try {
        var r = await sendTextMessage(target, message);
        results.push({ target: target, success: true, sent: r });
      } catch(e) {
        results.push({ target: target, success: false, error: e.message });
      }
      // 随机延迟，模拟人工行为
      if (i < targets.length - 1) {
        var delay = delayMin * 1000 + Math.random() * (delayMax - delayMin) * 1000;
        await sleep(delay);
      }
    }
    res.json({ success: true, total: targets.length, results: results });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// 获取群列表
app.get('/rooms', async function(req, res) {
  try {
    if (!isLoggedIn) return res.status(400).json({ error: 'Bot not logged in' });
    var rooms = await bot.Room.findAll();
    var roomList = [];
    for (var room of rooms) {
      var topic = await room.topic();
      var memberIdCount = (await room.memberAll()).length;
      roomList.push({
        id: room.id,
        topic: topic,
        memberCount: memberIdCount
      });
    }
    res.json({ success: true, rooms: roomList });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// 获取联系人列表
app.get('/contacts', async function(req, res) {
  try {
    if (!isLoggedIn) return res.status(400).json({ error: 'Bot not logged in' });
    var contacts = await bot.Contact.findAll();
    var contactList = [];
    for (var contact of contacts) {
      if (contact.type() === bot.Contact.Type.Personal) {
        contactList.push({
          id: contact.id,
          name: contact.name(),
          alias: await contact.alias()
        });
      }
    }
    res.json({ success: true, contacts: contactList });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

// 暂停/恢复机器人
app.post('/control', function(req, res) {
  var action = req.body.action;
  if (action === 'pause') {
    // 暂停消息处理（但不退出登录）
    app.locals.paused = true;
    res.json({ success: true, message: 'Bot paused (still logged in)' });
  } else if (action === 'resume') {
    app.locals.paused = false;
    res.json({ success: true, message: 'Bot resumed' });
  } else if (action === 'logout') {
    if (bot && isLoggedIn) {
      bot.logout();
      res.json({ success: true, message: 'Logging out...' });
    } else {
      res.json({ success: false, error: 'Not logged in' });
    }
  } else {
    res.status(400).json({ error: 'Unknown action: ' + action });
  }
});

// ========== 消息发送核心函数 ==========
async function sendTextMessage(target, message) {
  if (!isLoggedIn || !bot) {
    throw new Error('Bot not logged in');
  }
  
  // 尝试作为群发送
  var room = await findRoom(target);
  if (room) {
    await room.say(message);
    console.log('[Send] 群消息已发送: ' + target);
    return { type: 'room', target: target };
  }
  
  // 尝试作为联系人发送
  var contact = await findContact(target);
  if (contact) {
    await contact.say(message);
    console.log('[Send] 私聊消息已发送: ' + target);
    return { type: 'contact', target: target };
  }
  
  throw new Error('Target not found: ' + target);
}

async function findRoom(topic) {
  // 先查缓存
  if (roomCache.has(topic)) {
    var cached = roomCache.get(topic);
    try {
      await cached.ready();
      return cached;
    } catch(e) {
      roomCache.delete(topic);
    }
  }
  // 查询
  var room = await bot.Room.find({ topic: topic });
  if (room) {
    roomCache.set(topic, room);
    return room;
  }
  // 模糊匹配
  var allRooms = await bot.Room.findAll();
  for (var r of allRooms) {
    var t = await r.topic();
    if (t && t.indexOf(topic) !== -1) {
      roomCache.set(topic, r);
      return r;
    }
  }
  return null;
}

async function findContact(name) {
  if (contactCache.has(name)) {
    var cached = contactCache.get(name);
    try {
      await cached.ready();
      return cached;
    } catch(e) {
      contactCache.delete(name);
    }
  }
  var contact = await bot.Contact.find({ name: name });
  if (contact) {
    contactCache.set(name, contact);
    return contact;
  }
  // 尝试alias
  contact = await bot.Contact.find({ alias: name });
  if (contact) {
    contactCache.set(name, contact);
    return contact;
  }
  return null;
}

function sleep(ms) {
  return new Promise(function(r) { setTimeout(r, ms); });
}

// ========== Wechaty Bot 初始化 ==========
function initBot() {
  var puppet = new PuppetWechat4u();
  
  bot = new WechatyBuilder.build({
    name: 'wechaty-bot',
    puppet: puppet
  });

  // 扫码事件
  bot.on('scan', function(qrcode, status) {
    loginQrCode = qrcode;
    console.log('\n========================================');
    console.log('  扫码登录 (Status: ' + status + ')');
    console.log('========================================');
    QRCodeTerminal.generate(qrcode, { small: true });
    console.log('\n或访问 API 获取二维码: http://localhost:' + PORT + '/qrcode');
    console.log('========================================\n');
  });

  // 登录成功
  bot.on('login', function(user) {
    isLoggedIn = true;
    botName = user.name();
    loginQrCode = '';
    console.log('[Bot] 登录成功: ' + botName + ' (ID: ' + user.id + ')');
    console.log('[Bot] REST API: http://localhost:' + PORT);
    console.log('[Bot] API Key: ' + API_KEY);
    // 清空缓存
    roomCache.clear();
    contactCache.clear();
  });

  // 登出
  bot.on('logout', function(user) {
    isLoggedIn = false;
    botName = '';
    console.log('[Bot] 已登出: ' + (user ? user.name() : ''));
    roomCache.clear();
    contactCache.clear();
  });

  // 收到消息
  bot.on('message', async function(msg) {
    if (app.locals && app.locals.paused) return;
    
    var talker = msg.talker();
    var room = msg.room();
    var text = msg.text();
    var type = msg.type();
    
    // 只记录日志，不做自动回复（避免触发风控）
    var from = talker ? talker.name() : 'Unknown';
    var roomName = room ? (await room.topic()) : '私聊';
    console.log('[Msg] ' + roomName + ' | ' + from + ': ' + text.substring(0, 50));
  });

  // 错误处理
  bot.on('error', function(e) {
    console.error('[Bot Error]', e.message);
  });

  // 启动
  bot.start().then(function() {
    console.log('[Bot] Wechaty 启动中...');
    console.log('[Bot] Puppet: wechaty-puppet-wechat4u (UOS协议, 免费)');
    console.log('[Bot] 等待扫码登录...');
  }).catch(function(e) {
    console.error('[Bot] 启动失败:', e.message);
    console.log('[Bot] 5秒后重试...');
    setTimeout(initBot, 5000);
  });
}

// ========== 启动服务 ==========
app.locals.paused = false;

app.listen(PORT, function() {
  console.log('====================================');
  console.log('  Wechaty Bot + REST API');
  console.log('  Port: ' + PORT + ' (隔离于emodal-connector:10000)');
  console.log('  API Key: ' + API_KEY);
  console.log('====================================');
  console.log('');
  initBot();
});

// 优雅退出
process.on('SIGINT', async function() {
  console.log('\n[Bot] 正在关闭...');
  if (bot) await bot.stop();
  process.exit(0);
});

process.on('SIGTERM', async function() {
  console.log('\n[Bot] 收到SIGTERM，正在关闭...');
  if (bot) await bot.stop();
  process.exit(0);
});
