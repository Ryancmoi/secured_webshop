const db = require("../config/db");

module.exports = {
  // ----------------------------------------------------------
  // POST /api/auth/login
  // ----------------------------------------------------------
  login: (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email et mot de passe requis" });
    }

    const query = `SELECT * FROM users WHERE email = ? AND password = ?`;

    db.query(query, [email, password], (err, results) => {
      if (err) {
        return res.status(500).json({ error: err.message, query: query });
      }

      if (results.length === 0) {
        return res
          .status(401)
          .json({ error: "Email ou mot de passe incorrect" });
      }

      res.redirect("/");
    });
  },

  // ----------------------------------------------------------
  // POST /api/auth/register
  // ----------------------------------------------------------
  register: (req, res) => {
    const { username, address, email, password } = req.body;

    if (!email || !password || !username) {
      return res
        .status(400)
        .json({ error: "Tout les champs anotés d'un * sont obligatoires" });
    }

    const existingUserQuery = `SELECT * FROM users WHERE email = ?`;

    db.query(existingUserQuery, [email], (err, results) => {
      if (err) {
        return res.status(500).send("Erreur SQL");
      }

      if (results.length > 0) {
        res.status(409).json({ error: "Email déjà pris" });
      }
    });

    const sqlInsert = `INSERT INTO users (username, address, email, password) VALUES (?, ?, ?, ?)`;
  },
};
