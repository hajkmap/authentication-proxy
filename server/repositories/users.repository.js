import DatabaseService from "../services/database.service";

// This repository provides a way to handle users in the database without
// writing new statements every time.
class UsersRepository {
  constructor() {
    this.db = DatabaseService.usersDb;
  }

  // Add a new user
  create(user) {
    const { firstName, lastName, email, password, role, refreshToken } = user;
    const stmt = this.db.prepare(
      "INSERT INTO users (firstName, lastName, email, password, role, refreshToken) VALUES (?, ?, ?, ?, ?, ?)"
    );
    return stmt.run(firstName, lastName, email, password, role, refreshToken);
  }

  // Delete a user
  delete(user) {
    const { id } = user;
    const stmt = this.db.prepare("DELETE FROM users WHERE id = ?");
    return stmt.run(id);
  }

  // Get a user by email
  getUserByEmail(email) {
    const stmt = this.db.prepare("SELECT * FROM users WHERE email = ?");
    return stmt.get(email);
  }

  // Update refresh token
  updateRefreshToken(user, refreshToken) {
    const { id } = user;
    const stmt = this.db.prepare(
      "UPDATE users SET refreshToken = ? WHERE id = ?"
    );
    return stmt.run(refreshToken, id);
  }
}

export default new UsersRepository();
