import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pkg from "pg";
const { Pool } = pkg;

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: "15mb" })); 
app.use((req, res, next) => {
  const apiKey = req.headers["x-api-key"]; // cabeçalho personalizado
  const expectedKey = process.env.API_KEY;

  // Só exige API key para métodos que modificam dados
  const isProtected =
    req.method === "POST" ||
    req.method === "PATCH" ||
    req.method === "DELETE";

  if (isProtected && apiKey !== expectedKey) {
    return res.status(401).json({ error: "Acesso não autorizado" });
  }

  next();
});

// 🧠 conexão com o banco
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ✅ verifica conexão inicial
pool.connect()
  .then(() => console.log("✅ Conectado ao PostgreSQL!"))
  .catch(err => console.error("❌ Erro ao conectar:", err));

// ------------------- ROTAS -------------------

/**
 * GET /produtos → lista todos
 */
app.get("/produtos", async (_req, res) => {
  try {
    const result = await pool.query("SELECT * FROM produtos ORDER BY id DESC");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao buscar produtos" });
  }
});

/**
 * GET /produtos/:id → busca 1
 */
app.get("/produtos/:id", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM produtos WHERE id=$1", [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Produto não encontrado" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao buscar produto" });
  }
});

/**
 * POST /produtos → cria
 */
app.post("/produtos", async (req, res) => {
  try {
    const { titulo, preco, descricao, tamanhos, imagem_base64, valor_formatado, href } = req.body;

    const result = await pool.query(
      `INSERT INTO produtos (titulo, preco, descricao, tamanhos, imagem_base64, valor_formatado, href)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
      [titulo, preco, descricao, tamanhos, imagem_base64, valor_formatado, href]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao criar produto" });
  }
});

/**
 * PATCH /produtos/:id → atualiza campos específicos
 */
app.patch("/produtos/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const fields = ["titulo", "preco", "descricao", "tamanhos", "imagem_base64", "valor_formatado", "href"];
    const set = [];
    const values = [];
    fields.forEach((f) => {
      if (req.body[f] !== undefined) {
        set.push(`${f}=$${values.length + 1}`);
        values.push(req.body[f]);
      }
    });

    if (set.length === 0) return res.status(400).json({ error: "Nenhum campo para atualizar" });

    values.push(id);
    const query = `UPDATE produtos SET ${set.join(", ")} WHERE id=$${values.length} RETURNING *`;
    const result = await pool.query(query, values);

    if (result.rows.length === 0) return res.status(404).json({ error: "Produto não encontrado" });
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao atualizar produto" });
  }
});

/**
 * DELETE /produtos/:id → remove
 */
app.delete("/produtos/:id", async (req, res) => {
  try {
    const result = await pool.query("DELETE FROM produtos WHERE id=$1 RETURNING *", [req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: "Produto não encontrado" });
    res.json({ message: "Produto removido com sucesso" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Erro ao deletar produto" });
  }
});

// ------------------- INICIALIZA -------------------

const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`🚀 API rodando na porta ${PORT}`));
