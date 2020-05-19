import os
import bcrypt
from functools import wraps
from flask import Flask, render_template, url_for, request, redirect, session
from flask_pymongo import PyMongo
from bson.objectid import ObjectId

app = Flask(__name__)
app.secret_key = '>uRd*Mgt5NW.4_N9'
app.config["MONGO_URI"] = "mongodb://chrisjohnson98:asdf123@ds055742.mlab.com:55742/recipesite"
mongo = PyMongo(app)

site_path = os.path.realpath(os.path.dirname(__file__))

def check_auth(username, password):
	for item in mongo.db.users.find( {"user": username} ):
		valid = item['password']
		valid = valid.encode('utf-8')
		if valid == bcrypt.hashpw(password.encode('utf-8'), valid):
			return True
	return False	

def requires_login(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		status = session.get('logged_in', False)
		if not status:
			return redirect(url_for('index'))
		return f(*args, **kwargs)
	return decorated

def sessionCheck():
	if 'logged_in' not in session:
		session['logged_in'] = False
	if 'username' not in session:
		session['username'] = ""

@app.route('/')
def index():
	sessionCheck()
	return render_template('index.html', username = session['username'], loggedin = session['logged_in'])

@app.route('/share/',methods = ['POST', 'GET'])
@requires_login
def share():
	if request.method == 'POST':
		recipe_title = request.form['recipe_title']
		recipe_user = session['username']
		recipe_description = request.form['recipe_description']
		recipe_category = request.form['recipe_category']
		recipe_ingredients = request.form['recipe_ingredients']
		recipe_method = request.form['recipe_method']
		recipe_image = request.form['recipe_image']
		recipe_views = 0
		mongo.db.recipes.insert({"views": recipe_views, "user" : recipe_user, "title" : recipe_title, "category" : recipe_category, "ingredients" : recipe_ingredients, "method" : recipe_method, "img" : recipe_image, "description" : recipe_description})
		recipeID =+ 1
	return render_template('share.html', username = session['username'], loggedin = session['logged_in'])

@app.route('/recipes/')
def recipes():
	sessionCheck()
	recipes = mongo.db.recipes.find()
	return render_template('recipes.html', recipes = recipes, username = session['username'], loggedin = session['logged_in'])

@app.route('/recipes/<recipeID>', methods = ['POST', 'GET'])
def recipe(recipeID):
	sessionCheck()
	recipe = recipeID
	recipes = mongo.db.recipes.find()
	recipeview = mongo.db.recipes.find_one( {"title": recipe})
	recipeviews = recipeview['views']
	recipeviews = recipeviews + 1
	mongo.db.recipes.update_one( {"title": recipe }, {"$set": { "views": recipeviews }} )
	if request.method == 'POST':
		print(request.form['favourite'])
		favouriteid = request.form['favourite']
		user = session['username']
		useritem = mongo.db.users.find_one( {'user' : user } )
		useritem = useritem['_id']
		mongo.db.users.update_one( {'_id' : useritem}, {'$push': {'favourites': favouriteid }})
	return render_template('recipe.html', username = session['username'], loggedin = session['logged_in'], recipe = recipe, recipes = recipes)

@app.route('/category/<category>')
def category(category):
	sessionCheck()
	recipes = mongo.db.recipes.find()
	recipe_category = category
	return render_template('category.html', username = session['username'], loggedin = session['logged_in'], recipes = recipes, recipe_category = recipe_category)

@app.route('/myaccount/', methods = ['POST', 'GET'])
@requires_login
def myaccount():
	user = session['username']
	recipes = mongo.db.recipes.find()
	if request.method == 'POST':
		if 'delete' in request.form:
			recipeid = request.form['delete']
			mongo.db.recipes.remove( {"_id": ObjectId(recipeid) })
			return redirect(url_for('myaccount'))
	return render_template('myaccount.html', username = session['username'], loggedin = session['logged_in'], user = user, recipes = recipes)

@app.route('/favourites/', methods = ['POST', 'GET'])
@requires_login
def favourites():
	user = session['username']
	recipes = mongo.db.recipes.find()
	userfav = mongo.db.users.find_one( { 'user' : user } )
	favourites = []
	favouritesfinal = []
	for favourite in  userfav['favourites']:
		favourites.append(str(favourite))
	for recipe in recipes:
		if str(recipe['_id']) in favourites:
			favouritesfinal.append(recipe)
	return render_template('favourites.html', favourites = favouritesfinal, username = session['username'], loggedin = session['logged_in'], user = user, recipes = recipes)


@app.route('/user/<user>')
def users(user):
	sessionCheck()
	recipes = mongo.db.recipes.find()
	print(user)
	print(session['username'])
	if user == session['username']:
		return redirect(url_for('myaccount'))
	return render_template('user.html', username = session['username'], loggedin = session['logged_in'], user = user, recipes = recipes)

@app.route('/search/', methods = ['POST', 'GET'])
def searchinput():
	if request.method == 'POST':
		searchquery = request.form['newsearch']
		print(searchquery)
		return redirect(url_for('search', searchquery=searchquery))
	return redirect(url_for('index'))

@app.route('/search/<searchquery>')
def search(searchquery):
	sessionCheck()
	recipes = mongo.db.recipes.find()
	return render_template('search.html', username = session['username'], loggedin = session['logged_in'], searchquery=searchquery, recipes = recipes)

@app.route('/login/', methods = ['POST', 'GET'])
def login():
	sessionCheck()
	if request.method == 'POST':
		user = request.form['username']
		pw = request.form['password']
		
		if check_auth(request.form['username'], request.form['password']):
			session['logged_in'] = True
			session['username'] = user
			return redirect(url_for('index'))
	return render_template('login.html')

@app.route('/signup/', methods = ['POST', 'GET'])
def signup():
	sessionCheck()
	if request.method == 'POST':
		newuser = request.form['createusername']
		newpass = request.form['createpassword']
		favourites = []
		newpass = bcrypt.hashpw(newpass.encode('utf-8'), bcrypt.gensalt())	
		mongo.db.users.insert({"user": newuser, "password": newpass, "favourites": favourites})
		return redirect(url_for('login'))
	return render_template('signup.html')

@app.route('/logout/')
def logout():
	session['logged_in'] = False
	session['username'] = ""
	return redirect(url_for('index'))


if __name__ == "__main__":
	app.run(host='0.0.0.0', debug = True)
