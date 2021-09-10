import Database from "better-sqlite3";
import bcrypt from "bcrypt";

class DatabaseService {
  constructor() {
    // Initiate the database. If no database-file exists, it will be created.
    this.usersDb = new Database(process.env.USER_DATABASE_NAME, {
      verbose: console.log,
    });
    // Initiate the users table
    this.initiateUsersTable();
    // Add a admin user (that should be removed later)
    this.addPotentialFirstUser();
  }

  // Initiate the users table if it does not exist in the database.
  initiateUsersTable() {
    const sql = this.usersDb.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        firstName TEXT,
        lastName TEXT,
        email TEXT,
        password TEXT,
        role TEXT,
        refreshToken TEXT)`);
    sql.run();
  }

  // So that an admin can register the first "real" user, a mock-admin
  // is added if there are no users present in the table.
  addPotentialFirstUser() {
    // Let's check if we have any users in the users table
    const select = this.usersDb.prepare(`SELECT * FROM users`);
    const allUsers = select.all();
    // If we don't, we'll add one (so that the application can be used ;) )
    // Remember to remove this user when the first "real" user has been added!
    if (allUsers.length === 0) {
      const hash = bcrypt.hashSync(process.env.DEFAULT_ADMIN_PASSWORD, 10);
      const insertDefaultUser = this.usersDb.prepare(
        `INSERT INTO users (firstName, lastName, email, password, role, refreshToken) VALUES (?, ?, ?, ?, ?, ?)`
      );
      return insertDefaultUser.run(
        "Hajk",
        "Admin",
        process.env.DEFAULT_ADMIN_EMAIL,
        hash,
        "admin",
        null
      );
    }
  }
}

export default new DatabaseService();
