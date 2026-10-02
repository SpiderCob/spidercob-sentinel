import sqlite3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"


@app.route("/user")
def get_user(request):
    user_id = request.GET["id"]
    query = "SELECT * FROM users WHERE id=" + user_id
    conn = sqlite3.connect("db.sqlite")
    return conn.execute(query).fetchall()


def _dead_helper(request):
    # Never called anywhere and not decorated — should be flagged
    # "Unreachable" rather than HIGH.
    query = "SELECT * FROM users WHERE id=" + request.GET["id"]
    conn = sqlite3.connect("db.sqlite")
    return conn.execute(query).fetchall()
