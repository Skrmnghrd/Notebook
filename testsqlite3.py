import sqlite3 
from flask import Flask
from flask import g

DATABASE = 'test.db'

app = Flask(__name__)

"""
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sql.connect(DATABASE)
    #db.row_factory = sql.Row
    db.row_factory = sqlite3.Row

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        try:
            db = get_db()
            with app.open_resource('schema.sql', mode='r') as f:
                db.cursor().executescript(f.read())
            db.commit()
            print db
        except sqlite3.OperationalError: 
            print '[!] Something went wrong, or db exists'

def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    print 'err here'
    return (rv[0] if rv else None) if one else rv
"""
"""for i in range(100):
    with sqlite3.connect("test.db") as con:
        nm = 'name'
        addr = 'city'
        city = 'syudad'
        pin = 'pinn'
        cur = con.cursor()
        cur.execute("INSERT INTO students (name,addr,city,pin) VALUES (?,?,?,?)",(nm,addr,city,pin) )
        con.commit()

"""
"""user = query_db('select * from students')
if user is None:
    print 'None'
else:
    user['name']"""


#cur.executescript(create tables bla bla la)
def interact_with_db(db_name, query):
    con = sqlite3.connect(db_name)
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute(str(query))
    rows = cur.fetchall()
    cur.close
    return rows

"""
purchases = [('2006-03-28', 'BUY', 'IBM', 1000, 45.00),
             ('2006-04-05', 'BUY', 'MSFT', 1000, 72.00),
             ('2006-04-06', 'SELL', 'IBM', 500, 53.00),
            ]
c = conn.cursor()
c.executemany('INSERT INTO table VALUES (?,?,?,?)', purchases )
"""
"""for row in rows:
    print row["id"], row['addr'], row['city'], row['pin']"""
rows = interact_with_db('test.db','select * from students')
for things in rows:
    print things['id']
