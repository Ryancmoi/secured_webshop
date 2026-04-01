const db = require("../config/db");
const bcrypt = require("bcrypt");
const saltRounds = 10;

module.exports = {
  // ----------------------------------------------------------
  // POST /api/auth/login
  // ----------------------------------------------------------
  login: async (req, res) => {
    const { email, password } = req.body;
    try {
      if (!email || !password) {
        return res.status(400).json({ error: "Email et mot de passe requis" });
      }

      const query = `SELECT * FROM users WHERE email = ?`;

      db.query(query, [email], async (err, results) => {
        if (err) {
          return res.status(500).json({ error: err.message, query: query });
        }

        if (results.length === 0) {
          return res
            .status(401)
            .json({ error: "Email ou mot de passe incorrect" });
        }

        const isPassCorrect = await bcrypt.compare(password, res.password);

        if (isPassCorrect) {
          // SUCCÈS : Le mot de passe est correct
          console.log("Connexion réussie pour :", user.username);
          res.redirect("/");
        } else {
          // ÉCHEC : Mauvais mot de passe
          res.redirect("/login?error=invalid");
        }

        res.redirect("/");
      });
    } catch (error) {
      res.status(500).send("Erreur lors de la connexion");
    }
  },

  // ----------------------------------------------------------
  // POST /api/auth/register
  // ----------------------------------------------------------
  register: async (req, res) => {
    const { username, address, email, password } = req.body;

    if (!email || !password || !username) {
      return res
        .status(400)
        .json({ error: "Tout les champs anotés d'un * sont obligatoires" });
    }
    try {
      const salt = await bcrypt.genSalt(10);
      const secPassword = await bcrypt.hash(req.body.password, salt);

      const existingUserQuery = `SELECT * FROM users WHERE email = ?`;

      db.query(existingUserQuery, [email], (err, results) => {
        if (err) {
          return res.status(500).send("Erreur");
        }

        if (results.length > 0) {
          return res.status(409).json({ error: "Email déjà pris" });
        }

        const sqlInsert = `INSERT INTO users (username, address, email, password) VALUES (?, ?, ?, ?)`;

        db.query(
          sqlInsert,
          [username, address, email, secPassword],
          (sqlErr, sqlResults) => {
            if (sqlErr) {
              return res.status(500).send("Erreur SQL");
            }
            res.redirect("/?success=1");
          },
        );
      });
    } catch (error) {
      res.status(500).send("Erreur lors du hashage du mot de passe");
    }
  },
};
