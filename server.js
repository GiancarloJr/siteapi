import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Redis from "ioredis";

dotenv.config();

const { Pool } = pkg;

/** ===== Redis com TLS + SNI + IPv4 + retry/backoff ===== */
function createRedis() {
  const urlStr =
    process.env.CACHETOGO_TLS_URL ||  // rediss://...:443
    process.env.CACHETOGO_URL ||      // redis:// (fallback)
    process.env.REDIS_URL || null;

  if (!urlStr) return null;

  const u = new URL(urlStr);
  const isTls = u.protocol === "rediss:";

  const opts = {
    host: u.hostname,
    port: Number(u.port || (isTls ? 6380 : 6379)),
    username: u.username || undefined,
    password: u.password || undefined,

    family: 4,                 // ✅ força IPv4
    connectTimeout: 10000,
    keepAlive: 10000,
    lazyConnect: false,

    retryStrategy: (times) => Math.min(times * 500, 5000),
    maxRetriesPerRequest: null,
    enableReadyCheck: false,

    // ✅ TLS com SNI (servername) evita ECONNRESET em :443
    tls: isTls ? { rejectUnauthorized: false, servername: u.hostname } : undefined,
  };

  return new Redis(opts);
}

export const redis = createRedis();

if (redis) {
  console.log(
    "Redis URL ativa:",
    process.env.CACHETOGO_TLS_URL ? "CACHETOGO_TLS_URL" :
    process.env.CACHETOGO_URL ? "CACHETOGO_URL" :
    process.env.REDIS_URL ? "REDIS_URL" : "NENHUMA"
  );
  redis.on("connect", () => console.log("✅ Redis conectado"));
  redis.on("ready",   () => console.log("✅ Redis pronto"));
  redis.on("error",   (e) => {
    if (e?.code === "ECONNRESET") return; // silencia reset por idle
    console.error("❌ Redis erro:", e.message);
  });
  redis.on("end",     () => console.warn("⚠️  Redis desconectado"));
} else {
  console.warn("⚠️  Redis desativado (nenhuma URL no ambiente).");
}

const redisKey = (k) => `camaleao:${k}`;

const app = express();

const ALLOWED_ORIGINS = [
  "https://sitefabi.vercel.app",
  "http://localhost:4200",
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) callback(null, true);
    else callback(new Error("CORS: Origin não permitido"));
  },
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Authorization", "Content-Type"], 
  maxAge: 86400,
};

app.use(cors(corsOptions));

app.options("*", cors(corsOptions));

app.use((req, res, next) => {
  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }
  next();
});

app.use(express.json({ limit: "15mb" }));
app.use((req, res, next) => {
  if (req.path === "/auth/login") return next();
  if (req.method === "OPTIONS") return next();

  const isProtected =
    req.method === "POST" || req.method === "PATCH" || req.method === "DELETE";

  if (!isProtected) return next();

  const auth = req.headers["authorization"] || "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return res.status(401).json({ error: "Token ausente" });

  try {
    const payload = verifyToken(match[1]);
    if (payload?.role !== "admin") {
      return res.status(403).json({ error: "Sem permissão" });
    }
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido ou expirado" });
  }
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

pool
  .connect()
  .then(() => console.log("Conectado ao PostgreSQL!"))
  .catch((err) => console.error("Erro ao conectar:", err));

// ------------------- ROTAS -------------------

/**
 * POST /auth/login
 * body: { email, senha }
 * retorno: { token, user }
 */
app.post("/auth/login", async (req, res) => {
  try {
    const { email, senha } = req.body || {};
    if (!email || !senha) {
      return res.status(400).json({ error: "Email e senha são obrigatórios" });
    }

    const { rows } = await pool.query(
      "SELECT id, email, password_hash FROM usuarios_admin WHERE email = $1",
      [email]
    );
    if (!rows.length)
      return res.status(401).json({ error: "Credenciais inválidas" });

    const user = rows[0];
    const ok = await bcrypt.compare(senha, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Credenciais inválidas" });

    const token = signToken({ sub: user.id, email: user.email, role: "admin" });
    return res.json({
      token,
      user: { id: user.id, email: user.email },
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erro ao autenticar" });
  }
});

app.get("/produtos", cache(60), async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT p.id, p.titulo, p.preco, p.descricao, p.tamanhos, p.imagem_base64,
              p.valor_formatado, p.href, p.categoria_id, 
              c.nome AS categoria_nome, p.ativo
         FROM produtos p
    LEFT JOIN categorias c ON c.id = p.categoria_id
        ORDER BY p.id DESC`
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao buscar produtos" });
  }
});

app.get("/produtos/:id", cache(60), async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM produtos WHERE id=$1", [
      req.params.id,
    ]);
    if (result.rows.length === 0)
      return res.status(404).json({ error: "Produto não encontrado" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao buscar produto" });
  }
});

app.post("/produtos", async (req, res) => {
  try {
    const {
      titulo,
      preco,
      descricao,
      tamanhos,
      imagem_base64,
      valor_formatado,
      href,
      categoria_id,
    } = req.body;

    // validação básica
    if (!titulo || categoria_id == null) {
      return res
        .status(400)
        .json({ error: "Título e categoria_id são obrigatórios." });
    }

    // (opcional) validar existência da categoria
    const { rows: catRows } = await pool.query(
      "SELECT 1 FROM categorias WHERE id = $1",
      [categoria_id]
    );
    if (catRows.length === 0) {
      return res.status(400).json({ error: "Categoria inexistente." });
    }

    // garantir array de tamanhos (ou null)
    const tamanhosArray = Array.isArray(tamanhos) ? tamanhos : null;

    const result = await pool.query(
      `INSERT INTO produtos (
         titulo, preco, descricao, tamanhos, imagem_base64, valor_formatado, href, categoria_id
       ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id, titulo, preco, descricao, tamanhos, imagem_base64, valor_formatado, href, categoria_id`,
      [
        titulo,
        preco,
        descricao,
        tamanhosArray,
        imagem_base64,
        valor_formatado,
        href,
        categoria_id,
      ]
    );

    // se quiser já devolver a categoria junto, faça um JOIN após inserir:
    const { rows } = await pool.query(
      `SELECT p.*, c.nome AS categoria_nome, c.href AS categoria_href, c.path AS categoria_path
         FROM produtos p
         JOIN categorias c ON c.id = p.categoria_id
        WHERE p.id = $1`,
      [result.rows[0].id]
    );

    res.status(201).json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao criar produto" });
  } finally {
    invalidateProductsCache().catch(() => {});
  }
});

app.patch("/produtos/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const fields = [
      "titulo",
      "preco",
      "descricao",
      "tamanhos",
      "imagem_base64",
      "valor_formatado",
      "href",
      "categoria_id",
    ];

    if (req.body.categoria_id !== undefined) {
      const { rows: cat } = await pool.query(
        "SELECT 1 FROM categorias WHERE id = $1",
        [req.body.categoria_id]
      );
      if (!cat.length) {
        return res.status(400).json({ error: "Categoria inexistente." });
      }
    }

    const set = [];
    const values = [];

    fields.forEach((f) => {
      if (req.body[f] !== undefined) {
        set.push(`${f}=$${values.length + 1}`);
        values.push(req.body[f]);
      }
    });

    if (set.length === 0)
      return res.status(400).json({ error: "Nenhum campo para atualizar" });

    values.push(id);

    const query = `
      UPDATE produtos
         SET ${set.join(", ")}
       WHERE id = $${values.length}
       RETURNING id, titulo, preco, descricao, tamanhos, imagem_base64,
                 valor_formatado, href, categoria_id, ativo
    `;
    const updated = await pool.query(query, values);

    if (!updated.rows.length) {
      return res.status(404).json({ error: "Produto não encontrado" });
    }

    const { rows } = await pool.query(
      `SELECT p.*,
              c.nome AS categoria_nome,
              c.href AS categoria_href,
              c.path AS categoria_path
         FROM produtos p
    LEFT JOIN categorias c ON c.id = p.categoria_id
        WHERE p.id = $1`,
      [updated.rows[0].id]
    );

    return res.json(rows[0]);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Erro ao atualizar produto" });
  } finally {
    invalidateProductsCache().catch(() => {});
  }
});

app.get("/categorias/:id/produtos", cache(300),async (req, res) => {
  try {
    const categoriaId = Number(req.params.id);
    if (isNaN(categoriaId)) {
      return res.status(400).json({ error: "ID de categoria inválido." });
    }

    // verifica se a categoria existe
    const catResult = await pool.query(
      "SELECT * FROM categorias WHERE id = $1",
      [categoriaId]
    );
    if (catResult.rows.length === 0) {
      return res.status(404).json({ error: "Categoria não encontrada." });
    }

    const prodResult = await pool.query(
      `SELECT p.*, c.nome AS categoria_nome
         FROM produtos p
         JOIN categorias c ON p.categoria_id = c.id
        WHERE c.id = $1
     ORDER BY p.id DESC`,
      [categoriaId]
    );

    // resposta padronizada
    return res.json({
      categoria: catResult.rows[0],
      produtos: prodResult.rows,
    });
  } catch (err) {
    console.error("Erro em /categorias/:id/produtos:", err);
    return res
      .status(500)
      .json({ error: "Erro ao buscar produtos da categoria." });
  }
});

app.patch("/produtos/:id/ativo", async (req, res) => {
  const id = Number(req.params.id);
  const { ativo } = req.body; // boolean
  try {
    const { rows } = await pool.query(
      "UPDATE produtos SET ativo = $1 WHERE id = $2 RETURNING *",
      [ativo, id]
    );
    if (!rows.length) return res.status(404).json({ error: "Não encontrado" });
    res.json(rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao alterar ativo" });
  } finally {
    invalidateProductsCache().catch(() => {});
  }
});

app.delete("/produtos/:id", async (req, res) => {
  const id = Number(req.params.id);
  try {
    const { rowCount } = await pool.query(
      "DELETE FROM produtos WHERE id = $1",
      [id]
    );
    if (!rowCount) return res.status(404).json({ error: "Não encontrado" });
    res.status(204).end();
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Erro ao excluir" });
  } finally {
    invalidateProductsCache().catch(() => {});
  }
});

app.get("/categorias", cache(60), async (_req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, nome, path, href
         FROM categorias
        ORDER BY id ASC`
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao buscar categorias" });
  }
});

app.get("/test-redis", async (_req, res) => {
  try {
    if (!redis) return res.json({ ok: false, msg: "Redis OFF" });
    await redis.set("ping", "pong", "EX", 30);
    const val = await redis.get("ping");
    res.json({ ok: true, val });
  } catch (e) {
    res.status(500).json({ ok: false, err: e.message });
  }
});

function signToken(payload) {
  const secret = process.env.JWT_SECRET;
  return jwt.sign(payload, secret, { expiresIn: "2h" });
}

function verifyToken(token) {
  const secret = process.env.JWT_SECRET;
  return jwt.verify(token, secret);
}

function cache(ttlSec = 60) {
  return async (req, res, next) => {
    // Só GET idempotente
    if (req.method !== "GET" || !redis) return next();

    const key = redisKey(`cache:${req.method}:${req.originalUrl}`);
    try {
      const hit = await redis.get(key);
      if (hit) {
        res.set("X-Cache", "HIT");
        res.set("Cache-Control", "public, max-age=30, stale-while-revalidate=60");
        return res.type("application/json").send(hit);
      }
    } catch (e) {
      console.warn("Redis indisponível, seguindo sem cache:", e.message);
    }

    // Patch no send para escrever no cache após a resposta
    const originalSend = res.send.bind(res);
    res.send = async (body) => {
      try {
        if (res.statusCode === 200 && redis) {
          // garante string (res.json envia objeto)
          const payload = typeof body === "string" ? body : JSON.stringify(body);
          await redis.set(key, payload, "EX", ttlSec);
        }
      } catch {}
      res.set("X-Cache", "MISS");
      return originalSend(body);
    };

    next();
  };
}

async function invalidateProductsCache() {
  if (!redis) return;
  const pattern = redisKey("cache:GET:/produtos*");
  let cursor = "0";
  const keys = [];
  do {
    const [next, batch] = await redis.scan(cursor, "MATCH", pattern, "COUNT", 100);
    cursor = next;
    if (batch.length) keys.push(...batch);
  } while (cursor !== "0");
  if (keys.length) await redis.del(keys);
}



// ------------------- INICIALIZA -------------------

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 API rodando na porta ${PORT}`));
