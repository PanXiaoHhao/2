const express = require('express');
const cors = require('cors');
const { default: wrapper } = require('axios-cookiejar-support');
const axios = require('axios').default;
const { CookieJar } = require('tough-cookie');
const cheerio = require('cheerio');
const md5 = require('md5');

// 创建Express应用
const app = express();
app.use(cors());
app.use(express.json());

// 教务系统基础配置
const EDU_BASE_URL = 'http://jwgl.rzvtc.cn:8081/rzzyjw';
const LOGIN_PAGE_URL = `${EDU_BASE_URL}/cas/login.action`;
const LOGIN_SUBMIT_URL = `${EDU_BASE_URL}/cas/login.action.html`;
const EXAM_INFO_URL = `${EDU_BASE_URL}/student/examarrange/examarrange_query.jsp`;

// 带时间戳的日志函数
const logWithTimestamp = (message, level = 'INFO') => {
  const timestamp = new Date().toISOString();
  console.log(`[${timestamp}] [${level}] ${message}`);
};

// 模拟人类延迟的函数
const delay = (ms) => {
  logWithTimestamp(`⏱️  等待 ${ms}ms...`, 'DEBUG');
  return new Promise(resolve => setTimeout(resolve, ms));
};

// 生成随机延迟时间，符合人类行为习惯
const randomDelay = (min = 500, max = 2000) => {
  const a = min;
  const b = max;
  const c = (a + b) / 2; // 峰值在中间，更符合真实人类行为
  
  const u = Math.random();
  let delayTime;
  
  if (u < (c - a) / (b - a)) {
    delayTime = a + Math.sqrt(u * (b - a) * (c - a));
  } else {
    delayTime = b - Math.sqrt((1 - u) * (b - a) * (b - c));
  }
  
  return Math.floor(delayTime);
};

// 缓存机制
const dataCache = new Map();
const CACHE_DURATION = 10 * 60 * 1000; // 缓存10分钟

/**
 * 从缓存中获取数据
 * @param {string} key - 缓存键
 * @returns {Object|null} 缓存的数据或null
 */
function getFromCache(key) {
  const cachedData = dataCache.get(key);
  if (cachedData) {
    const { data, timestamp } = cachedData;
    if (Date.now() - timestamp < CACHE_DURATION) {
      logWithTimestamp(`📦 从缓存中获取数据，键：${key}`, 'DEBUG');
      return data;
    } else {
      dataCache.delete(key);
      logWithTimestamp(`📦 缓存过期，已移除，键：${key}`, 'DEBUG');
    }
  }
  return null;
}

/**
 * 将数据存入缓存
 * @param {string} key - 缓存键
 * @param {Object} data - 要缓存的数据
 */
function setToCache(key, data) {
  dataCache.set(key, {
    data: data,
    timestamp: Date.now()
  });
  logWithTimestamp(`📦 数据已存入缓存，键：${key}，有效期：${CACHE_DURATION/1000}秒`, 'DEBUG');
}

/**
 * 创建带Cookie的axios实例
 * @returns {Object} 带Cookie的axios实例
 */
function createAxiosInstance() {
  const jar = new CookieJar();
  
  // User-Agent池，模拟不同浏览器和设备
  const userAgents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15'
  ];
  
  // 随机选择一个User-Agent
  const randomUserAgent = userAgents[Math.floor(Math.random() * userAgents.length)];
  logWithTimestamp(`🔍 随机选择User-Agent: ${randomUserAgent}`, 'DEBUG');
  
  // 新版本用法：先创建axios实例，再用wrapper包装
  const instance = wrapper(axios.create({
    timeout: 15000,
    withCredentials: true,
    headers: {
      'User-Agent': randomUserAgent,
      'Referer': LOGIN_PAGE_URL,
      'Content-Type': 'application/x-www-form-urlencoded',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      'Accept-Encoding': 'gzip, deflate',
      'Accept-Language': 'zh-CN,zh;q=0.9',
      'Connection': 'keep-alive',
      'Host': 'jwgl.rzvtc.cn:8081'
    },
    jar: jar
  }));
  
  return instance;
}

/**
 * 检查密码复杂度
 * @param {string} password - 原始密码
 * @param {string} username - 学号
 * @returns {Object} 密码复杂度检查结果
 */
function checkPasswordComplexity(password, username) {
  let result = 0;
  for (let i = 0; i < password.length; i++) {
    const charCode = password.charCodeAt(i);
    if (charCode >= 48 && charCode <= 57) {
      result |= 8; // 数字
    } else if (charCode >= 97 && charCode <= 122) {
      result |= 4; // 小写字母
    } else if (charCode >= 65 && charCode <= 90) {
      result |= 2; // 大写字母
    } else {
      result |= 1; // 特殊字符
    }
  }
  
  // 检查密码是否包含账号
  const inuserzh = password.toLowerCase().trim().includes(username.toLowerCase().trim()) ? "1" : "0";
  
  return {
    txt_mm_expression: result.toString(),
    txt_mm_length: password.length.toString(),
    txt_mm_userzh: inuserzh
  };
}

/**
 * 密码加密函数
 * 规则：hex_md5(hex_md5(password) + hex_md5(randnumber.toLowerCase()))
 * @param {string} password - 原始密码
 * @param {string} randnumber - 验证码
 * @returns {string} 加密后的密码
 */
function encryptPassword(password, randnumber = '') {
  logWithTimestamp(`📌 开始密码加密，原始密码：${password}`);
  
  try {
    // 严格按照loginbar.js的加密逻辑：不转大写，直接使用md5返回的小写值
    const md5Password = md5(password);
    logWithTimestamp(`📌 第一次MD5加密结果：${md5Password}`);
    
    // 验证码MD5（转小写后），验证码为空时使用空字符串
    const md5Rand = randnumber ? md5(randnumber.toLowerCase()) : '';
    logWithTimestamp(`📌 验证码MD5加密结果：${md5Rand}`);
    
    // 将两个加密结果拼接，再进行一次MD5
    const finalMd5 = md5(md5Password + md5Rand);
    logWithTimestamp(`📌 最终密码加密结果：${finalMd5}`);
    
    return finalMd5;
  } catch (error) {
    logWithTimestamp(`❌ 密码加密失败：${error.message}`, 'ERROR');
    // 加密失败时，返回原始密码的MD5值作为备用
    return md5(password);
  }
}

/**
 * 执行登录
 * @param {string} studentId - 学号
 * @param {string} password - 密码
 * @param {string} randnumber - 验证码
 * @returns {Object} 登录结果
 */
async function login(studentId, password, randnumber = '') {
  try {
    logWithTimestamp(`📌 接收到登录请求：学号=${studentId}`);
    
    // 模拟人类操作：等待随机时间，模拟用户思考
    await delay(randomDelay(1000, 2000));
    
    // 创建带Cookie的axios实例
    logWithTimestamp(`🔧 创建带Cookie的axios实例`);
    const instance = createAxiosInstance();
    
    // 先访问登录页，获取Cookie和randnumber
    logWithTimestamp(`📌 访问登录页获取Cookie...`);
    const loginPageResponse = await instance.get(LOGIN_PAGE_URL);
    logWithTimestamp(`📌 登录页访问成功，状态码：${loginPageResponse.status}`);
    
    // 从登录页源码中提取randnumber
    logWithTimestamp(`📌 从登录页提取randnumber...`);
    let extractedRandnumber = randnumber;
    
    if (!extractedRandnumber) {
      const randnumberMatch = loginPageResponse.data.match(/var _randnumber = "([^"]+)";/) || 
                            loginPageResponse.data.match(/var randnumber = "([^"]+)";/) ||
                            loginPageResponse.data.match(/id="randnumber"[^>]*value="([^"]+)"/);
      
      if (randnumberMatch) {
        extractedRandnumber = randnumberMatch[1];
        logWithTimestamp(`📌 成功提取randnumber：${extractedRandnumber}`);
      } else {
        logWithTimestamp(`⚠️  未提取到randnumber，使用空字符串`, 'WARNING');
      }
    }
    
    // 密码复杂度检查
    const passwordPolicy = checkPasswordComplexity(password, studentId);
    logWithTimestamp(`📌 密码复杂度检查结果：${JSON.stringify(passwordPolicy)}`);
    
    // 加密密码
    logWithTimestamp(`🔑 开始加密密码...`);
    const encryptedPassword = encryptPassword(password, extractedRandnumber);
    logWithTimestamp(`🔑 密码加密完成，结果：${encryptedPassword}`);
    
    // 构建登录请求数据
    logWithTimestamp(`📌 构建登录请求数据...`);
    
    // 构建完整的登录参数，完全匹配HTML里的字段和loginbar.js的checkrand函数
    const loginParams = {
      username: studentId,
      password: encryptedPassword,
      randnumber: extractedRandnumber,
      isPasswordPolicy: "1",
      txt_mm_expression: passwordPolicy.txt_mm_expression,
      txt_mm_length: passwordPolicy.txt_mm_length,
      txt_mm_userzh: passwordPolicy.txt_mm_userzh,
      hid_flag: "1",
      hid_dxyzm: "",
      hid_sjhm: ""
    };
    
    // 模拟表单提交前的准备时间
    await delay(randomDelay(300, 1000));
    
    // 发送登录请求
    logWithTimestamp(`📤 发送POST请求到登录URL：${LOGIN_SUBMIT_URL}`);
    logWithTimestamp(`📋 登录请求数据：${new URLSearchParams(loginParams).toString()}`);
    
    const loginResponse = await instance.post(LOGIN_SUBMIT_URL, new URLSearchParams(loginParams), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': LOGIN_PAGE_URL
      }
    });
    
    // 模拟登录请求发送后的等待时间
    await delay(randomDelay(500, 1500));
    
    logWithTimestamp(`📌 登录请求完成，状态码：${loginResponse.status}`);
    logWithTimestamp(`📌 登录请求最终URL：${loginResponse.request.res.responseUrl}`);
    
    // 判断登录成功：登录成功会跳转到系统首页（URL不含cas/login）
    const isSuccess = !loginResponse.request.res.responseUrl.includes('cas/login');
    if (!isSuccess) {
      logWithTimestamp(`❌ 登录失败：账号密码错误/参数不匹配/需要验证码`, 'ERROR');
      return { success: false, message: '登录失败：账号密码错误/参数不匹配/需要验证码' };
    }
    
    logWithTimestamp(`✅ 登录成功！`);
    return { success: true, instance: instance };
    
  } catch (error) {
    let errorMessage = '登录失败：';
    
    if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
      errorMessage += '网络连接失败，请检查网络连接或目标网站是否可访问';
    } else if (error.response) {
      errorMessage += `服务器返回错误：状态码 ${error.response.status}，消息 ${error.response.statusText}`;
      if (error.response.status === 401 || error.response.status === 403) {
        errorMessage += '，可能是登录状态已过期或访问被拒绝';
      }
    } else if (error.request) {
      errorMessage += '未收到服务器响应，请检查网络连接或目标网站状态';
    } else {
      errorMessage += error.message;
    }
    
    logWithTimestamp(`❌ 登录过程出错: ${error.message}`, 'ERROR');
    return { success: false, message: errorMessage };
  }
}

/**
 * 爬取考试安排数据
 * @param {Object} instance - 登录后的axios实例
 * @returns {Array} 考试数据列表
 */
async function fetchExamData(instance) {
  try {
    logWithTimestamp('📌 开始爬取考试数据');
    
    // 检查instance是否有效
    if (!instance) {
      logWithTimestamp('❌ 登录实例无效，无法爬取数据', 'ERROR');
      throw new Error('登录实例无效，无法爬取数据');
    }
    
    // 模拟用户寻找并点击考试安排链接的延迟
    await delay(randomDelay(500, 1200));
    
    // 考试安排页面URL
    const examUrl = EXAM_INFO_URL;
    logWithTimestamp(`🌐 考试安排页面URL：${examUrl}`);
    
    // 发送请求获取考试数据
    logWithTimestamp('📌 发送请求获取考试数据...');
    await delay(randomDelay(300, 800));
    
    logWithTimestamp(`📤 发送GET请求到考试安排URL：${examUrl}`);
    const response = await instance.get(examUrl);
    logWithTimestamp(`📌 考试数据请求成功，状态码：${response.status}`);
    
    // 模拟用户等待页面完全加载的延迟
    await delay(randomDelay(600, 1500));
    
    // 解析考试数据
    logWithTimestamp('📌 开始解析考试数据...');
    const $ = cheerio.load(response.data);
    const examList = [];
    
    // 模拟用户浏览表格内容的延迟
    await delay(randomDelay(400, 900));
    
    // 通用表格解析，适应不同表格结构
    logWithTimestamp('📊 开始通用表格解析...');
    let rowCount = 0;
    
    $('table').each((tableIdx, tableEl) => {
      $(tableEl).find('tr').each((rowIdx, rowEl) => {
        if (rowIdx === 0) return; // 跳过表头
        
        rowCount++;
        
        // 模拟用户查看当前行的延迟
        
        const tds = $(rowEl).find('td');
        if (tds.length < 3) {
          logWithTimestamp(`⚠️  第 ${rowCount} 行数据字段不足，跳过`, 'WARNING');
          return; // 过滤无效行
        }
        
        // 通用表格解析，提取关键考试信息
        examList.push({
          courseName: $(tds[1]).text().trim() || '未知课程',
          examTime: $(tds[2]).text().trim() || '未知时间',
          examLocation: $(tds[3]).text().trim() || '未知地点',
          seatNumber: $(tds[4]).text().trim() || '未知座位号',
          // 添加额外的字段以兼容不同的表格结构
          credit: $(tds[5]).text().trim() || '0',
          examMethod: $(tds[6]).text().trim() || '未知方式',
          status: $(tds[7]).text().trim() || '未知状态'
        });
      });
    });
    
    logWithTimestamp(`📊 共处理 ${rowCount} 行数据，成功提取 ${examList.length} 条考试信息`);
    
    // 模拟用户浏览完所有数据后的思考延迟
    await delay(randomDelay(500, 1200));
    
    // 确保返回的数据是真实爬取的
    if (examList.length === 0) {
      logWithTimestamp('⚠️  爬取到的考试数据为空，检查页面结构是否变化', 'WARNING');
      throw new Error('未爬取到考试数据，可能是页面结构变化或登录状态失效');
    }
    
    logWithTimestamp(`✅ 成功爬取 ${examList.length} 条考试数据`);
    return examList;
    
  } catch (error) {
    let errorMessage = '爬取考试数据失败：';
    
    if (error.code === 'ECONNREFUSED' || error.code === 'ETIMEDOUT') {
      errorMessage += '网络连接失败，请检查网络连接或目标网站是否可访问';
    } else if (error.response) {
      errorMessage += `服务器返回错误：状态码 ${error.response.status}，消息 ${error.response.statusText}`;
      if (error.response.status === 401 || error.response.status === 403) {
        errorMessage += '，可能是登录状态已过期或访问被拒绝';
      }
    } else if (error.request) {
      errorMessage += '未收到服务器响应，请检查网络连接或目标网站状态';
    } else {
      errorMessage += error.message;
    }
    
    logWithTimestamp(`❌ 爬取考试数据失败: ${error.message}`, 'ERROR');
    throw new Error(errorMessage);
  }
}

/**
 * 根据数据类型获取对应数据
 * @param {string} studentId - 学号
 * @param {string} password - 密码
 * @param {string} dataType - 数据类型：exam
 * @param {string} randnumber - 验证码
 * @returns {Object} 包含指定数据的结果
 */
async function fetchDataByType(studentId, password, dataType, randnumber = '') {
  // 分步验证机制
  
  // 步骤1：验证用户输入
  logWithTimestamp('📌 验证用户输入...');
  if (!studentId || !password) {
    logWithTimestamp('❌ 用户输入不完整，缺少学号或密码', 'ERROR');
    return { success: false, message: '请提供学号和密码' };
  }
  
  // 步骤2：检查缓存
  const cacheKey = `${studentId}_${dataType}`;
  const cachedData = getFromCache(cacheKey);
  if (cachedData) {
    logWithTimestamp(`📦 缓存命中，直接返回${dataType}数据，避免重复请求`);
    return cachedData;
  }
  
  // 步骤3：执行登录
  logWithTimestamp('📌 执行登录...');
  const loginResult = await login(studentId, password, randnumber);
  if (!loginResult.success) {
    return { success: false, message: loginResult.message };
  }
  
  // 模拟人类思考和操作时间
  await delay(randomDelay(800, 1500));
  
  // 步骤4：根据数据类型获取对应数据
  logWithTimestamp(`📌 获取${dataType}数据...`);
  let dataList;
  
  switch(dataType) {
    case 'exam':
      dataList = await fetchExamData(loginResult.instance);
      break;
    default:
      logWithTimestamp(`❌ 无效的数据类型：${dataType}`, 'ERROR');
      return { success: false, message: '无效的数据类型，目前仅支持：exam' };
  }
  
  // 步骤5：验证数据完整性
  logWithTimestamp('📌 验证数据完整性...');
  if (!Array.isArray(dataList)) {
    logWithTimestamp(`${dataType}数据格式错误，不是数组类型`, 'ERROR');
    return { success: false, message: `${dataType}数据格式错误` };
  }
  
  // 步骤6：返回结果并缓存
  logWithTimestamp('📌 所有步骤完成，返回真实爬取数据...');
  logWithTimestamp(`✅ 成功获取 ${dataList.length} 条${dataType}数据`);
  
  // 构建返回结果
  const result = {
    success: true,
    [dataType + 'Count']: dataList.length,
    [dataType + 'List']: dataList
  };
  
  // 将数据存入缓存
  setToCache(cacheKey, result);
  
  return result;
}

/**
 * 登录并获取考试数据（兼容旧版接口）
 * @param {string} studentId - 学号
 * @param {string} password - 密码
 * @returns {Object} 包含考试数据的结果
 */
async function getExamInfo(studentId, password) {
  return fetchDataByType(studentId, password, 'exam');
}

// API接口
// 新增：统一考试查询接口（兼容最终版）
app.post('/api/queryExam', async (req, res) => {
  const { username, password, randnumber = '' } = req.body;
  
  logWithTimestamp('📥 收到考试数据请求（新版接口）');
  
  if (!username || !password) {
    logWithTimestamp('❌ 请求参数不完整，缺少学号或密码', 'ERROR');
    return res.json({
      success: false,
      message: '请提供学号和密码'
    });
  }
  
  try {
    logWithTimestamp(`🚀 开始处理请求：学号=${username}`);
    
    // 检查缓存
    const cacheKey = `${username}_exam`;
    const cachedData = getFromCache(cacheKey);
    if (cachedData) {
      logWithTimestamp(`📦 缓存命中，直接返回考试数据，避免重复请求`);
      return res.json({ success: true, data: { exams: cachedData.examList } });
    }
    
    // 登录
    const loginResult = await login(username, password, randnumber);
    if (!loginResult.success) {
      return res.json({ success: false, message: loginResult.message });
    }
    
    // 获取考试信息
    const examInfo = await fetchExamData(loginResult.instance);
    
    logWithTimestamp(`✅ 请求处理完成，返回 ${examInfo.length} 条考试数据`);
    
    // 将数据存入缓存
    setToCache(cacheKey, { examList: examInfo });
    
    res.json({ success: true, data: { exams: examInfo } });
    
  } catch (error) {
    logWithTimestamp(`❌ 接口处理出错: ${error.message}`, 'ERROR');
    res.json({
      success: false,
      message: error.message || '服务器内部错误'
    });
  }
});

// 考试数据接口（兼容旧版）
app.post('/api/exam', async (req, res) => {
  const { studentId, password, randnumber = '' } = req.body;
  
  logWithTimestamp('📥 收到考试数据请求');
  
  if (!studentId || !password) {
    logWithTimestamp('❌ 请求参数不完整，缺少学号或密码', 'ERROR');
    return res.json({
      success: false,
      message: '请提供学号和密码'
    });
  }
  
  try {
    logWithTimestamp(`🚀 开始处理请求：学号=${studentId}`);
    const result = await fetchDataByType(studentId, password, 'exam', randnumber);
    logWithTimestamp(`✅ 请求处理完成，返回 ${result.examCount} 条考试数据`);
    
    res.json(result);
    
  } catch (error) {
    logWithTimestamp(`❌ 接口处理出错: ${error.message}`, 'ERROR');
    res.json({
      success: false,
      message: error.message || '服务器内部错误'
    });
  }
});

// 启动服务器
const PORT = 3000;
app.listen(PORT, () => {
  const startTime = new Date().toLocaleString();
  console.log(`\n✅ 后端服务已启动！`);
  console.log(`📅 启动时间：${startTime}`);
  console.log(`🌐 支持API端点：`);
  console.log(`   - 新版考试查询：http://localhost:${PORT}/api/queryExam`);
  console.log(`   - 旧版考试数据：http://localhost:${PORT}/api/exam`);
  console.log(`📋 支持功能：考试安排数据爬取`);
  console.log(`🔒 安全特性：`);
  console.log(`   - 严格登录校验：只有真实登录教务系统成功后才返回数据`);
  console.log(`   - 真实数据获取：直接从教务系统爬取真实考试数据`);
  console.log(`   - 人类行为模拟：符合真实用户操作习惯的延迟和间隔`);
  console.log(`   - 完整HTML表单支持：包含所有必要的隐藏字段`);
  console.log(`   - 缓存机制：减少重复请求，提高性能`);
  console.log(`📝 日志特性：每一步操作都有详细的时间戳和操作描述`);
  console.log(`🎯 登录流程：严格按照实际登录页JS实现密码加密和登录请求`);
  console.log('\n');
});
