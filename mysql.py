from ast import Return
from unicodedata import name
from flask import Flask,render_template,request,jsonify,make_response
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash,check_password_hash
import uuid
import jwt
import datetime
from lib2to3.pgen2 import token
from functools import wraps
app=Flask(__name__)

app.config['MYSQL_HOST']="localhost"
app.config['MYSQL_USER']="root"
app.config['MYSQL_PASSWORD']=""
app.config['MYSQL_DB']="database_flask"
app.config['SECRET_KEY']='thisissecret'
mysql=MySQL(app)



def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token=None

        if 'x-access-token' in request.headers:
            token=request.headers['x-access-token']

        if not token :
            return jsonify({'message':'Token is missing!'}),401
        try:
            data=jwt.decode(token,app.config['SECRET_KEY'])
            cur=mysql.connection.cursor()
            sql="SELECT * FROM User WHERE public_id= %s"
            val=(data['public_id'],)
            users=cur.execute(sql,val)
            
            userDetails=cur.fetchall()
            for user in userDetails:
                current_user=user
                
        except:
            return jsonify({'message':'Token is invalid!'}),401
            
        return f(current_user,*args,**kwargs)
    return decorated    

## add a new user
@app.route('/',methods=['GET','POST'])
def index():
    ## for the post 
    if request.method=='POST':
        name=request.form['username']
        password=request.form['password']
        hashed_password=generate_password_hash(password,method='sha256')
        public_id=str(uuid.uuid4())
        cur=mysql.connection.cursor()
        cur.execute("INSERT INTO User (name,password,public_id) Values (%s,%s,%s)",(name,hashed_password,public_id))
        mysql.connection.commit()
        cur.close()
        
  
    return render_template('index.html')

#return users list 
@app.route('/users',methods=['GET']) 
@token_required
def show_users(current_user):

    if not current_user[4]:
      return jsonify({'message':'Cannot perform that function!'})


    cur=mysql.connection.cursor()
    users=cur.execute("SELECT * FROM User")
    if users>0:
        userDetails=cur.fetchall()
    output=[]
    for user in userDetails:
        user_data={}
        user_data['public_id']=user[1]
        user_data['name']=user[2]
        user_data['password']=user[3]
        user_data['admin']=user[4]
        output.append(user_data)
    return jsonify({'users':output})

#get one user by its public id 
@app.route('/users/<public_id>',methods=['GET'])
@token_required
def get_one_user(current_user,public_id):

    if not current_user[4]:
      return jsonify({'message':'Cannot perform that function!'})



    cur=mysql.connection.cursor()
    sql="SELECT * FROM User WHERE public_id= %s"
    val=(public_id,)
    users=cur.execute(sql,val)
    
    if not users:
        return jsonify({'message':'no user found!'})
    
    userDetails=cur.fetchall()
    output=[]
    for user in userDetails:
        d1={}
        d1['public_id']=user[1]
        d1['name']=user[2]
        d1['password']=user[3]
        d1['admin']=user[4]
        output.append(d1)
    return jsonify({'user':output})

#promote a user
@app.route('/users/<public_id>',methods=['PUT'])
@token_required
def promote_user(current_user,public_id):
    
    if not current_user[4]:
      return jsonify({'message':'Cannot perform that function!'})

    
    cur=mysql.connection.cursor()
    sql="SELECT * FROM User WHERE public_id= %s"
    val=(public_id,)
    users=cur.execute(sql,val)
    
    if not users:
        return jsonify({'message':'no user found!'})

    sql1="UPDATE User SET admin = %s WHERE public_id= %s"
    val1=(True,public_id)
    users=cur.execute(sql1,val1)
    mysql.connection.commit()
    
    return jsonify({'message':'the user has been promoted!'})

#delete a user 
@app.route('/users/<public_id>',methods=['DELETE'])
@token_required
def delete_user(current_user,public_id):

    if not current_user[4]:
      return jsonify({'message':'Cannot perform that function!'})


    cur=mysql.connection.cursor()
    sql="SELECT * FROM User WHERE public_id= %s"
    val=(public_id,)
    users=cur.execute(sql,val)

    if not users:
        return jsonify({'message':'no user found!'})

    sql1="DELETE FROM User WHERE public_id = %s"
    val1=(public_id,)
    cur.execute(sql1,val1)
    mysql.connection.commit()

    return jsonify({'message':'The user has been deleted!'})






#login
@app.route('/login',methods=['GET'])
def login():
    
    auth=request.authorization 
    
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login required!"'})
    
    cur=mysql.connection.cursor()
    sql="SELECT * FROM User WHERE name= %s"
    val=(auth.username,)
    user=cur.execute(sql,val)

    if not user:
        return make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login required!"'})
    
    userDetails=cur.fetchall()
    output=[]
    for user in userDetails:
        d1={}
        d1['public_id']=user[1]
        d1['name']=user[2]
        d1['password']=user[3]
        d1['admin']=user[4]
        output.append(d1)


    if check_password_hash(d1['password'],auth.password):
        token=jwt.encode({'public_id':d1['public_id'],'exp':datetime.datetime.utcnow()+datetime.timedelta(minutes=30)},app.config['SECRET_KEY'])
        return token

    return  make_response('Could not verify',401,{'WWW-Authenticate':'Basic realm="Login required!"'})








#Assign an article (completed)
@app.route('/article',methods=['POST'])
@token_required
def create_article(current_user):
    if not current_user[4]:
      return jsonify({'message':'Cannot perform that function!'})
    data=request.get_json()
    user_id=data['user_id']
    text=data['text']
    words_required=data['words_required']
    name=data['name']
    cur=mysql.connection.cursor()
    cur.execute("INSERT INTO articles (user_id,text,words_required,name) Values (%s,%s,%s,%s)",(user_id,text,words_required,name))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message':'article assigned'})

#discover all articles (completed)
@app.route('/article',methods=['GET'])
@token_required
def get_all_articles(current_user):
    
    cur=mysql.connection.cursor()
    sql="SELECT * FROM articles WHERE user_id= %s"
    val=(current_user[1],)
    assinged=cur.execute(sql,val)
    
    if not assinged:
        return jsonify({'message':'no articles found'})

    total_articles=cur.fetchall()
    output=[]
    for article in total_articles:
        d1={}
        d1['user_id']=article[1]
        d1['text']=article[2]
        d1['name']=article[3]
        d1['word_required']=article[4]
        d1['publish_status']=article[5]
        output.append(d1)
    return jsonify({'articles':output})


#work on the article (completed)
@app.route('/article/<user_id>',methods=['PUT'])
@token_required
def editbook(current_user,user_id):
    
    if not (current_user[1]==user_id):
      return jsonify({'message':'Cannot perform that function!'})

    
    data=request.get_json()
    text=data['text']

    cur=mysql.connection.cursor()
    sql="SELECT * FROM articles WHERE user_id= %s"
    val=(user_id,)
    assinged=cur.execute(sql,val)
    
    if not assinged:
        return jsonify({'message':'no articles found!'})

    sql1="UPDATE articles SET text = %s WHERE user_id= %s"
    val1=(text,user_id)
    users=cur.execute(sql1,val1)
    mysql.connection.commit()
    
    return jsonify({'message':'the article is good to go'})

#delete an article (completed)
@app.route('/article/<user_id>/<name>',methods=['DELETE'])
@token_required
def delete_article(current_user,user_id,name):
    if not current_user[4]:
      return jsonify({'message':'Cannot perform that function!'})


    cur=mysql.connection.cursor()
    sql="SELECT * FROM articles WHERE user_id= %s"
    val=(user_id,)
    users=cur.execute(sql,val)

    if not users:
        return jsonify({'message':'no articles found!'})

    sql1="DELETE FROM articles WHERE user_id = %s AND name=%s"
    val1=(user_id,name)
    cur.execute(sql1,val1)
    mysql.connection.commit()

    return jsonify({'message':'The article is deleted'})





if __name__=="__main__":
    app.run(debug=True)