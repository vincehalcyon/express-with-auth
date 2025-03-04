const mysql = require("mysql2/promise");

async function query(sql, params) {
  const connection = await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "root",
    database: "crud_db",
  });

  const [results] = await connection.execute(sql, params);

  return results;
}

module.exports = {
  query,
};
