const apiKey = "sk-live-abc123xyz";
const password = "admin123";

function fetchUser(userInput) {
  const query = `SELECT * FROM users WHERE id = ${userInput}`;
  return query;
}

function dangerousEval(expression) {
  return eval(expression);
}

function runCommand(cmd) {
  return exec(cmd);
}

module.exports = { fetchUser, dangerousEval, runCommand };
