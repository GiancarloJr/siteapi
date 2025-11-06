import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { randomUUID } from "crypto";
import { v2 as cloudinary } from "cloudinary";

const { Pool } = pkg;

dotenv.config();

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

const app = express();

const ALLOWED_ORIGINS = [
  "https://www.camaleaostorerv.com.br",
  "https://sitefabi.vercel.app",
  "http://localhost:4200",
];

const corsOptions = {
  origin: (origin, callback) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("CORS: Origin não permitido"));
    }
  },
  methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Authorization", "Content-Type", "x-api-key"],
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

app.get("/produtos", async (_req, res) => {
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

app.get("/produtos/:id", async (req, res) => {
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

    if (!titulo || categoria_id == null) {
      return res
        .status(400)
        .json({ error: "Título e categoria_id são obrigatórios." });
    }

    const { rows: catRows } = await pool.query(
      "SELECT 1 FROM categorias WHERE id = $1",
      [categoria_id]
    );
    if (!catRows.length)
      return res.status(400).json({ error: "Categoria inexistente." });

    const tamanhosArray =
      Array.isArray(tamanhos) && tamanhos.length
        ? tamanhos.map((s) => String(s).trim()).filter(Boolean)
        : null;

    const precoNum =
      preco === null || preco === undefined || preco === ""
        ? null
        : Number(preco);
    if (precoNum !== null && Number.isNaN(precoNum))
      return res.status(400).json({ error: "Preço inválido." });

    if (!href && !imagem_base64) {
      return res
        .status(400)
        .json({ error: "Envie 'href' ou 'imagem_base64'." });
    }

    let finalHref = href ?? null;
    if (!finalHref && imagem_base64) {
      const { secureUrl } = await uploadDataUrlToCloudinary(imagem_base64);
      finalHref = secureUrl;
    }

    const valorFormatado =
      valor_formatado ?? (precoNum != null ? precoNum.toFixed(2) : null);

    const insert = await pool.query(
      `INSERT INTO produtos (titulo, preco, descricao, tamanhos, imagem_base64, valor_formatado, href, categoria_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id`,
      [
        titulo,
        precoNum,
        descricao ?? null,
        tamanhosArray,
        null,
        valorFormatado,
        finalHref,
        categoria_id,
      ]
    );

    const { rows } = await pool.query(
      `SELECT p.*, c.nome AS categoria_nome, c.href AS categoria_href, c.path AS categoria_path
         FROM produtos p
         JOIN categorias c ON c.id = p.categoria_id
        WHERE p.id = $1`,
      [insert.rows[0].id]
    );

    res.status(201).json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao criar produto" });
  }
});

app.patch("/produtos/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (Number.isNaN(id))
      return res.status(400).json({ error: "ID inválido." });

    const { rows: existingRows } = await pool.query(
      "SELECT * FROM produtos WHERE id = $1",
      [id]
    );
    if (!existingRows.length)
      return res.status(404).json({ error: "Produto não encontrado." });

    let {
      titulo,
      preco,
      descricao,
      tamanhos,
      imagem_base64, // se vier, substitui imagem
      valor_formatado,
      href, // se vier e não houver base64, atualiza
      categoria_id,
    } = req.body;

    // normalizações
    const fields = {};
    if (titulo !== undefined) fields.titulo = String(titulo);
    if (preco !== undefined) {
      const n = preco === null || preco === "" ? null : Number(preco);
      if (n !== null && Number.isNaN(n))
        return res.status(400).json({ error: "Preço inválido." });
      fields.preco = n;
    }
    if (descricao !== undefined) fields.descricao = descricao ?? null;
    if (tamanhos !== undefined) {
      fields.tamanhos =
        Array.isArray(tamanhos) && tamanhos.length
          ? tamanhos.map((s) => String(s).trim()).filter(Boolean)
          : null;
    }
    if (categoria_id !== undefined) fields.categoria_id = categoria_id ?? null;

    // imagem: se veio base64, sobrepõe; senão, se veio href, usa href
    if (imagem_base64) {
      const { secureUrl } = await uploadDataUrlToCloudinary(imagem_base64);
      fields.href = secureUrl;
      fields.imagem_base64 = null; // nunca persistimos base64
    } else if (href !== undefined) {
      fields.href = href || null;
      fields.imagem_base64 = null;
    }

    if (valor_formatado !== undefined) {
      fields.valor_formatado = valor_formatado ?? null;
    } else if (fields.preco !== undefined) {
      fields.valor_formatado =
        fields.preco != null ? fields.preco.toFixed(2) : null;
    }

    // monta UPDATE dinâmico
    const set = [];
    const values = [];
    Object.entries(fields).forEach(([k, v]) => {
      set.push(`${k}=$${values.length + 1}`);
      values.push(v);
    });

    if (!set.length)
      return res.status(400).json({ error: "Nenhum campo para atualizar." });

    values.push(id);
    const query = `UPDATE produtos SET ${set.join(", ")} WHERE id=$${
      values.length
    } RETURNING *`;
    const result = await pool.query(query, values);

    const updated = result.rows[0];

    const { rows } = await pool.query(
      `SELECT p.*, c.nome AS categoria_nome, c.href AS categoria_href, c.path AS categoria_path
         FROM produtos p
         JOIN categorias c ON c.id = p.categoria_id
        WHERE p.id = $1`,
      [updated.id]
    );

    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao atualizar produto" });
  }
});

app.get("/categorias/:id/produtos", async (req, res) => {
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
  }
});

app.get("/categorias", async (_req, res) => {
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

async function uploadDataUrlToCloudinary(dataUrl) {
  if (!/^data:image\/(png|jpe?g|webp);base64,/i.test(dataUrl || "")) {
    throw new Error("Formato de imagem inválido. Envie uma Data URL base64.");
  }

  const publicId = `camaleao/produtos/${randomUUID()}`; // nome único
  const result = await cloudinary.uploader.upload(dataUrl, {
    folder: "camaleao/produtos",
    public_id: publicId.split("/").pop(),
    overwrite: false,
    invalidate: false,
    resource_type: "image",
    // otimização automática no delivery
    transformation: [{ fetch_format: "auto", quality: "auto" }],
  });

  return { secureUrl: result.secure_url, publicId: result.public_id };
}

// ------------------- INICIALIZA -------------------

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 API rodando na porta ${PORT}`));
