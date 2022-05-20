from flask import Flask, request, redirect, session, make_response, jsonify, Response  # Import flask
from flaskext.mysql import MySQL
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes
import secrets
import base64
import json


app = Flask(__name__, static_url_path='')

mysql = MySQL(autocommit=True)
app.config['MYSQL_DATABASE_HOST'] = 'localhost'
app.config['MYSQL_DATABASE_USER'] = 'cryptoadmin'
app.config['MYSQL_DATABASE_PASSWORD'] = ''
app.config['MYSQL_DATABASE_DB'] = 'cryptocode'
mysql.init_app(app)

userids = {};

conn = mysql.connect()
cursor = conn.cursor()
cursor.execute(f"DELETE FROM users;")
cursor.close()

@app.errorhandler(404)
def page_not_found(e):
    return app.send_static_file('index.html')

@app.route('/')
def home():
    return app.send_static_file('index.html')

@app.route('/reload', methods=['POST', 'GET'])
def reload():
    return(redirect('/'))

@app.route('/submitflag', methods = ['POST'])
def submitflag():
    print(f"remote: {request.path}")
    if 'userID' in request.cookies:
        userID = request.cookies.get('userID')
        user = request.cookies.get('user')
        try:
            userids[user]
        except:
            resp = make_response(redirect('/reload'))
            resp.set_cookie('userID', '', expires=0)
            resp.set_cookie('user', '', expires=0)
            return(resp)
        
        if userids[user] == userID:
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM challenges WHERE name='{request.json['name']}'")
            data = cursor.fetchone()
            flag = data[2]
            challpoints = data[3]
            if request.json['flag'] == flag:
                cursor.execute(f"SELECT * FROM users WHERE username='{user}'")
                data = cursor.fetchone()
                points = data[4]
                solved = json.loads(base64.b64decode(data[8]).decode('ascii'))["solved"]
                solved.append(request.json['name'])
                userdata = base64.b64encode(json.dumps({"solved": solved}).encode()).decode()
                cursor.execute(f"UPDATE users SET points={points+challpoints} WHERE username='{user}'")
                cursor.execute(f"UPDATE users SET data='{userdata}' WHERE username='{user}'")
                cursor.close()
                return Response(json.dumps({'Flag':'Correct', "solved": solved}), status=200, mimetype='application/json')
            return Response(json.dumps({'Flag':'Incorrect'}), status=200, mimetype='application/json')
    resp = make_response(redirect('/reload'))
    resp.set_cookie('userID', '', expires=0)
    resp.set_cookie('user', '', expires=0)
    return(resp)


@app.route('/userAPI', methods = ['GET'])
def userAPI():
    if 'userID' in request.cookies:
        userID = request.cookies.get('userID')
        user = request.cookies.get('user')
        try:
            userids[user]
        except:
            resp = make_response(redirect('/reload'))
            resp.set_cookie('userID', '', expires=0)
            resp.set_cookie('user', '', expires=0)
            return(resp)
          
        if userids[user] == userID:
            conn = mysql.connect()
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM users WHERE username='{user}'")
            data = cursor.fetchone()
            cursor.close()
            points = data[4]
            level = data[5]
            country = data[7]
            solved = json.loads(base64.b64decode(data[8]).decode('ascii'))["solved"]
            resp = make_response(json.dumps({"points": points, "level": level, "country": country, "solved": solved}))
            print(resp)
            return resp
        else:
            resp = make_response(redirect('/reload'))
            resp.set_cookie('userID', '', expires=0)
            resp.set_cookie('user', '', expires=0)
            return(resp)
    resp = make_response(redirect('/reload'))
    resp.set_cookie('userID', '', expires=0)
    resp.set_cookie('user', '', expires=0)
    return(resp)


@app.route('/login',methods = ['POST', 'GET'])
def login():
   if request.method == 'POST':
      user = request.form['username']
      conn = mysql.connect()
      cursor = conn.cursor()
      cursor.execute(f"SELECT * FROM users WHERE username='{user}'")
      data = cursor.fetchone()
      cursor.close()
      print(data)
      salt = long_to_bytes(int(data[2],16))
      hash = long_to_bytes(int(data[3],16))
      m = SHA256.new()
      m.update(salt+request.form['password'].encode())
      password = m.digest()
      if password==hash:
          print("got password right")
          resp = make_response(redirect('/AUTH.js'))
          resp.set_cookie('user', user)
          sessionid = secrets.token_bytes(128).hex()
          resp.set_cookie('userID', sessionid)
          userids[user] = sessionid
      else:
          print("password")
          resp = make_response(redirect('/AUTH.js'))
      return resp
   else:
      user = request.args.get('username')
      conn = mysql.connect()
      cursor = conn.cursor()
      cursor.execute(f"SELECT * FROM users WHERE username='{user}'")
      data = cursor.fetchone()
      cursor.close()
      print(data)
      salt = long_to_bytes(int(data[2],16))
      hash = long_to_bytes(int(data[3],16))
      m = SHA256.new()
      m.update(salt+request.args.get('password').encode())
      password = m.digest()
      if password==hash:
          print("got password right")
          resp = make_response(redirect('/'))
          resp.set_cookie('user', user)
          sessionid = secrets.token_bytes(128).hex()
          resp.set_cookie('userID', sessionid)
          userids[user] = sessionid
      else:
          print("password")
          resp = make_response(redirect('/'))
      return resp

@app.route('/signup',methods = ['POST', 'GET'])
def signup():
   if request.method == 'POST':
      user = request.form['username']
      conn = mysql.connect()
      cursor = conn.cursor()
      cursor.execute(f"SELECT * FROM users WHERE username='{user}'")
      data = cursor.fetchone()
      print(data)
      if (data == None):
        salt = secrets.token_bytes(32)
        m = SHA256.new()
        m.update(salt+request.form['password'].encode())
        password = hex(bytes_to_long(m.digest()))
        print(f"password: {password}")
        salt = hex(bytes_to_long(salt))
        userdata = base64.b64encode(json.dumps({"solved": []}).encode()).decode()
        req = f"INSERT INTO users(username, salt, password, data) VALUES (\"{user}\", \"{salt}\", \"{password}\", \"{userdata}\")"
        print(len(salt))
        print(req)
        cursor.execute(req)
        cursor.close()
      return redirect('/AUTH.js')
   else:
      user = request.args.get('username')
      conn = mysql.connect()
      cursor = conn.cursor()
      cursor.execute(f"SELECT * FROM users WHERE username='{user}'")
      data = cursor.fetchone()
      print(data)
      if (data == None):
        salt = secrets.token_bytes(32)
        m = SHA256.new()
        m.update(salt+request.args.get('password').encode())
        password = hex(bytes_to_long(m.digest()))
        print(f"password: {password}")
        salt = hex(bytes_to_long(salt))
        userdata = base64.b64encode(json.dumps({"solved": []}).encode()).decode()
        req = f"INSERT INTO users(username, salt, password, data) VALUES (\"{user}\", \"{salt}\", \"{password}\", \"{userdata}\")"
        print(len(salt))
        print(req)
        cursor.execute(req)
        cursor.close()
      return redirect('/AUTH.js')

if __name__ == '__main__':  # If the script that was run is this script (we have not been imported)
    app.run(debug=True)  # Start the server