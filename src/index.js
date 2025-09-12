import { Router } from 'itty-router';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';

// 创建路由器
const router = Router();

// 中间件：验证用户是否已登录
const authMiddleware = async (request, env) => {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const token = authHeader.split(' ')[1];
  // 在实际应用中，这里应该验证JWT令牌
  // 简化版本，仅检查用户ID
  try {
    const userId = token;
    const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(userId).first();
    if (!user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    request.user = user;
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

// 注册用户
router.post('/api/register', async (request, env) => {
  try {
    const { email, password } = await request.json();

    // 验证输入
    if (!email || !password) {
      return new Response(JSON.stringify({ error: 'Email and password are required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 检查用户是否已存在
    const existingUser = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
    if (existingUser) {
      return new Response(JSON.stringify({ error: 'User already exists' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 哈希密码
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // 创建用户
    const userId = uuidv4();
    const now = Date.now();

    await env.DB.prepare(
      'INSERT INTO users (id, email, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(userId, email, passwordHash, now, now).run();

    // 创建默认保管库
    const vaultId = uuidv4();
    await env.DB.prepare(
      'INSERT INTO vaults (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(vaultId, userId, 'My Vault', now, now).run();

    return new Response(JSON.stringify({ id: userId, email }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 用户登录
router.post('/api/login', async (request, env) => {
  try {
    const { email, password } = await request.json();

    // 验证输入
    if (!email || !password) {
      return new Response(JSON.stringify({ error: 'Email and password are required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 查找用户
    const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
    if (!user) {
      return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 验证密码
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 在实际应用中，这里应该生成JWT令牌
    // 简化版本，直接返回用户ID作为令牌
    return new Response(JSON.stringify({ token: user.id, user: { id: user.id, email: user.email } }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 获取用户保管库
router.get('/api/vaults', authMiddleware, async (request, env) => {
  try {
    const vaults = await env.DB.prepare('SELECT * FROM vaults WHERE user_id = ?').bind(request.user.id).all();
    return new Response(JSON.stringify(vaults.results), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 创建新保管库
router.post('/api/vaults', authMiddleware, async (request, env) => {
  try {
    const { name } = await request.json();

    // 验证输入
    if (!name) {
      return new Response(JSON.stringify({ error: 'Vault name is required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const vaultId = uuidv4();
    const now = Date.now();

    await env.DB.prepare(
      'INSERT INTO vaults (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(vaultId, request.user.id, name, now, now).run();

    return new Response(JSON.stringify({ id: vaultId, name }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 获取保管库中的所有项目
router.get('/api/vaults/:vaultId/items', authMiddleware, async (request, env) => {
  try {
    const { vaultId } = request.params;

    // 验证保管库是否属于当前用户
    const vault = await env.DB.prepare('SELECT * FROM vaults WHERE id = ? AND user_id = ?')
      .bind(vaultId, request.user.id).first();
    if (!vault) {
      return new Response(JSON.stringify({ error: 'Vault not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const items = await env.DB.prepare('SELECT * FROM items WHERE vault_id = ? AND user_id = ?')
      .bind(vaultId, request.user.id).all();
    return new Response(JSON.stringify(items.results), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 创建新项目（密码、登录信息等）
router.post('/api/vaults/:vaultId/items', authMiddleware, async (request, env) => {
  try {
    const { vaultId } = request.params;
    const { type, name, data, favorite = 0 } = await request.json();

    // 验证输入
    if (!type || !name || !data) {
      return new Response(JSON.stringify({ error: 'Type, name and data are required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 验证保管库是否属于当前用户
    const vault = await env.DB.prepare('SELECT * FROM vaults WHERE id = ? AND user_id = ?')
      .bind(vaultId, request.user.id).first();
    if (!vault) {
      return new Response(JSON.stringify({ error: 'Vault not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const itemId = uuidv4();
    const now = Date.now();

    await env.DB.prepare(
      'INSERT INTO items (id, vault_id, user_id, type, name, favorite, data, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(itemId, vaultId, request.user.id, type, name, favorite, JSON.stringify(data), now, now).run();

    return new Response(JSON.stringify({ id: itemId, type, name, favorite, data }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 获取单个项目详情
router.get('/api/items/:itemId', authMiddleware, async (request, env) => {
  try {
    const { itemId } = request.params;

    const item = await env.DB.prepare('SELECT * FROM items WHERE id = ? AND user_id = ?')
      .bind(itemId, request.user.id).first();
    if (!item) {
      return new Response(JSON.stringify({ error: 'Item not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 解析存储的JSON数据
    item.data = JSON.parse(item.data);

    return new Response(JSON.stringify(item), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 更新项目
router.put('/api/items/:itemId', authMiddleware, async (request, env) => {
  try {
    const { itemId } = request.params;
    const { type, name, data, favorite } = await request.json();

    // 验证项目是否属于当前用户
    const item = await env.DB.prepare('SELECT * FROM items WHERE id = ? AND user_id = ?')
      .bind(itemId, request.user.id).first();
    if (!item) {
      return new Response(JSON.stringify({ error: 'Item not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const now = Date.now();
    const updates = [];
    const values = [];

    if (type) {
      updates.push('type = ?');
      values.push(type);
    }

    if (name) {
      updates.push('name = ?');
      values.push(name);
    }

    if (data) {
      updates.push('data = ?');
      values.push(JSON.stringify(data));
    }

    if (favorite !== undefined) {
      updates.push('favorite = ?');
      values.push(favorite);
    }

    updates.push('updated_at = ?');
    values.push(now);

    // 添加itemId和userId作为WHERE条件的参数
    values.push(itemId);
    values.push(request.user.id);

    const query = `UPDATE items SET ${updates.join(', ')} WHERE id = ? AND user_id = ?`;
    await env.DB.prepare(query).bind(...values).run();

    // 获取更新后的项目
    const updatedItem = await env.DB.prepare('SELECT * FROM items WHERE id = ?').bind(itemId).first();
    updatedItem.data = JSON.parse(updatedItem.data);

    return new Response(JSON.stringify(updatedItem), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 删除项目
router.delete('/api/items/:itemId', authMiddleware, async (request, env) => {
  try {
    const { itemId } = request.params;

    // 验证项目是否属于当前用户
    const item = await env.DB.prepare('SELECT * FROM items WHERE id = ? AND user_id = ?')
      .bind(itemId, request.user.id).first();
    if (!item) {
      return new Response(JSON.stringify({ error: 'Item not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 删除项目
    await env.DB.prepare('DELETE FROM items WHERE id = ?').bind(itemId).run();

    return new Response(JSON.stringify({ message: 'Item deleted successfully' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 创建文件夹
router.post('/api/folders', authMiddleware, async (request, env) => {
  try {
    const { name } = await request.json();

    // 验证输入
    if (!name) {
      return new Response(JSON.stringify({ error: 'Folder name is required' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const folderId = uuidv4();
    const now = Date.now();

    await env.DB.prepare(
      'INSERT INTO folders (id, user_id, name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(folderId, request.user.id, name, now, now).run();

    return new Response(JSON.stringify({ id: folderId, name }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 获取所有文件夹
router.get('/api/folders', authMiddleware, async (request, env) => {
  try {
    const folders = await env.DB.prepare('SELECT * FROM folders WHERE user_id = ?').bind(request.user.id).all();
    return new Response(JSON.stringify(folders.results), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 将项目添加到文件夹
router.post('/api/items/:itemId/folders/:folderId', authMiddleware, async (request, env) => {
  try {
    const { itemId, folderId } = request.params;

    // 验证项目是否属于当前用户
    const item = await env.DB.prepare('SELECT * FROM items WHERE id = ? AND user_id = ?')
      .bind(itemId, request.user.id).first();
    if (!item) {
      return new Response(JSON.stringify({ error: 'Item not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 验证文件夹是否属于当前用户
    const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ? AND user_id = ?')
      .bind(folderId, request.user.id).first();
    if (!folder) {
      return new Response(JSON.stringify({ error: 'Folder not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 检查关联是否已存在
    const existing = await env.DB.prepare('SELECT * FROM item_folders WHERE item_id = ? AND folder_id = ?')
      .bind(itemId, folderId).first();
    if (existing) {
      return new Response(JSON.stringify({ message: 'Item already in folder' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 添加关联
    await env.DB.prepare('INSERT INTO item_folders (item_id, folder_id) VALUES (?, ?)')
      .bind(itemId, folderId).run();

    return new Response(JSON.stringify({ message: 'Item added to folder successfully' }), {
      status: 201,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 从文件夹中移除项目
router.delete('/api/items/:itemId/folders/:folderId', authMiddleware, async (request, env) => {
  try {
    const { itemId, folderId } = request.params;

    // 验证项目是否属于当前用户
    const item = await env.DB.prepare('SELECT * FROM items WHERE id = ? AND user_id = ?')
      .bind(itemId, request.user.id).first();
    if (!item) {
      return new Response(JSON.stringify({ error: 'Item not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 验证文件夹是否属于当前用户
    const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ? AND user_id = ?')
      .bind(folderId, request.user.id).first();
    if (!folder) {
      return new Response(JSON.stringify({ error: 'Folder not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 删除关联
    await env.DB.prepare('DELETE FROM item_folders WHERE item_id = ? AND folder_id = ?')
      .bind(itemId, folderId).run();

    return new Response(JSON.stringify({ message: 'Item removed from folder successfully' }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 获取文件夹中的所有项目
router.get('/api/folders/:folderId/items', authMiddleware, async (request, env) => {
  try {
    const { folderId } = request.params;

    // 验证文件夹是否属于当前用户
    const folder = await env.DB.prepare('SELECT * FROM folders WHERE id = ? AND user_id = ?')
      .bind(folderId, request.user.id).first();
    if (!folder) {
      return new Response(JSON.stringify({ error: 'Folder not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 获取文件夹中的所有项目
    const items = await env.DB.prepare(`
      SELECT i.* FROM items i
      JOIN item_folders if ON i.id = if.item_id
      WHERE if.folder_id = ? AND i.user_id = ?
    `).bind(folderId, request.user.id).all();

    // 解析每个项目的JSON数据
    const results = items.results.map(item => {
      return {
        ...item,
        data: JSON.parse(item.data)
      };
    });

    return new Response(JSON.stringify(results), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 搜索项目
router.get('/api/search', authMiddleware, async (request, env) => {
  try {
    const url = new URL(request.url);
    const query = url.searchParams.get('q') || '';
    const type = url.searchParams.get('type');

    let sql = `
      SELECT * FROM items 
      WHERE user_id = ? AND name LIKE ?
    `;
    const params = [request.user.id, `%${query}%`];

    if (type) {
      sql += ' AND type = ?';
      params.push(type);
    }

    const items = await env.DB.prepare(sql).bind(...params).all();

    // 解析每个项目的JSON数据
    const results = items.results.map(item => {
      return {
        ...item,
        data: JSON.parse(item.data)
      };
    });

    return new Response(JSON.stringify(results), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// 处理CORS预检请求
router.options('*', () => {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
    },
  });
});

// 404处理
router.all('*', () => {
  return new Response(JSON.stringify({ error: 'Not Found' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json' }
  });
});

// 导出Worker处理函数
export default {
  async fetch(request, env, ctx) {
    // 添加CORS头
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    // 处理请求
    const response = await router.handle(request, env, ctx);
    
    // 添加CORS头到响应
    const newResponse = new Response(response.body, response);
    Object.keys(corsHeaders).forEach(key => {
      newResponse.headers.set(key, corsHeaders[key]);
    });
    
    return newResponse;
  },
};