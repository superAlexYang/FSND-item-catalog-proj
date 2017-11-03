from flask import Flask, jsonify,render_template, request, redirect, jsonify, url_for, flash
from flask import session as login_session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, ToyShop, ToyItem, User
from functions_helper import *
import random, string

from oauth2client.client import AccessTokenRefreshError
import httplib2
import json
from flask import make_response
import requests

import os

path = os.path.dirname(__file__)

app = Flask(__name__)

engine = create_engine('postgresql://catalog:catalog123@localhost/catalog')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

import random, string, json, httplib2, requests
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']

def initUser(login):
    newUser = User(name=login['username'], email=login['email'], picture=login['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login['email']).one()
    return user.id

def userInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def userID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

@app.route('/')
@app.route('/catalog')
def showCategories():
	categories = session.query(Category).all()
	categoryItems = session.query(CategoryItem).all()
	return render_template('categories.html', categories = categories, categoryItems = categoryItems)

@app.route('/catalog/<int:catalog_id>')
@app.route('/catalog/<int:catalog_id>/items')
def showCategory(catalog_id):
	categories = session.query(Category).all()
	category = session.query(Category).filter_by(id = catalog_id).first()
	categoryName = category.name
	categoryItems = session.query(CategoryItem).filter_by(category_id = catalog_id).all()
	categoryItemsCount = session.query(CategoryItem).filter_by(category_id = catalog_id).count()
	return render_template('category.html', categories = categories, categoryItems = categoryItems, categoryName = categoryName, categoryItemsCount = categoryItemsCount)

@app.route('/catalog/<int:catalog_id>/items/<int:item_id>')
def showCategoryItem(catalog_id, item_id):
	categoryItem = session.query(CategoryItem).filter_by(id = item_id).first()
	creator = userInfo(categoryItem.user_id)
	return render_template('categoryItem.html', categoryItem = categoryItem, creator = creator)

@app.route('/catalog/add', methods=['GET', 'POST'])
def addCategoryItem():
	if 'username' not in login_session:
	    return redirect('/login')
	if request.method == 'POST':
		if not request.form['name']:
			flash('Please add instrument name')
			return redirect(url_for('addCategoryItem'))
		if not request.form['description']:
			flash('Please add a description')
			return redirect(url_for('addCategoryItem'))
		newCategoryItem = CategoryItem(name = request.form['name'], description = request.form['description'], category_id = request.form['category'], user_id = login_session['user_id'])
		session.add(newCategoryItem)
		session.commit()
		return redirect(url_for('showCategories'))
	else:
		categories = session.query(Category).all()
		return render_template('addCategoryItem.html', categories = categories)

@app.route('/catalog/<int:catalog_id>/items/<int:item_id>/edit', methods=['GET', 'POST'])
def editCategoryItem(catalog_id, item_id):
	if 'username' not in login_session:
	    return redirect('/login')
	categoryItem = session.query(CategoryItem).filter_by(id = item_id).first()
	creator = userInfo(categoryItem.user_id)
	if creator.id != login_session['user_id']:
		return redirect('/login')
	categories = session.query(Category).all()
	if request.method == 'POST':
		if request.form['name']:
			categoryItem.name = request.form['name']
		if request.form['description']:
			categoryItem.description = request.form['description']
		if request.form['category']:
			categoryItem.category_id = request.form['category']
		return redirect(url_for('showCategoryItem', catalog_id = categoryItem.category_id ,item_id = categoryItem.id))
	else:
		return render_template('editCategoryItem.html', categories = categories, categoryItem = categoryItem)

@app.route('/catalog/<int:catalog_id>/items/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteCategoryItem(catalog_id, item_id):
	if 'username' not in login_session:
	    return redirect('/login')
	categoryItem = session.query(CategoryItem).filter_by(id = item_id).first()
	creator = userInfo(categoryItem.user_id)
	if creator.id != login_session['user_id']:
		return redirect('/login')
	if request.method == 'POST':
		session.delete(categoryItem)
		session.commit()
		return redirect(url_for('showCategory', catalog_id = categoryItem.category_id))
	else:
		return render_template('deleteCategoryItem.html', categoryItem = categoryItem)

@app.route('/login')
def login():
	state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
	login_session['state'] = state

	return render_template('login.html', STATE=state)

@app.route('/logout')
def logout():
	if login_session['provider'] == 'google':
		gdisconnect()
		del login_session['gplus_id']
		del login_session['access_token']

	del login_session['username']
	del login_session['email']
	del login_session['picture']
	del login_session['user_id']
	del login_session['provider']

	return redirect(url_for('showCategories'))

@app.route('/gconnect', methods=['POST'])
def gconnect():
	if request.args.get('state') != login_session['state']:
		response = make_response(json.dumps('Invalid state parameter.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	code = request.data

	try:
		oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
		oauth_flow.redirect_uri = 'postmessage'
		credentials = oauth_flow.step2_exchange(code)
	except FlowExchangeError:
		response = make_response(json.dumps('Failed to upgrade the authorization code.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	access_token = credentials.access_token
	url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
	h = httplib2.Http()
	result = json.loads(h.request(url, 'GET')[1])

	if result.get('error') is not None:
		response = make_response(json.dumps(result.get('error')), 500)
		response.headers['Content-Type'] = 'application/json'
		return response

	gplus_id = credentials.id_token['sub']
	if result['user_id'] != gplus_id:
		response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	if result['issued_to'] != CLIENT_ID:
		response = make_response(json.dumps("Token's client ID does not match app's."), 401)
		print "Token's client ID does not match app's."
		response.headers['Content-Type'] = 'application/json'
		return response

	stored_access_token = login_session.get('access_token')
	stored_gplus_id = login_session.get('gplus_id')

	if stored_access_token is not None and gplus_id == stored_gplus_id:
		response = make_response(json.dumps('Current user is already connected.'), 200)
		response.headers['Content-Type'] = 'application/json'
		return response

	login_session['access_token'] = credentials.access_token
	login_session['gplus_id'] = gplus_id

	userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
	params = {'access_token': credentials.access_token, 'alt': 'json'}
	answer = requests.get(userinfo_url, params=params)

	data = answer.json()

	login_session['username'] = data['name']
	login_session['picture'] = data['picture']
	login_session['email'] = data['email']
	login_session['provider'] = 'google'

	user_id = userID(data["email"])
	if not user_id:
	    user_id = initUser(login_session)
	login_session['user_id'] = user_id

	return "Login Successful"

@app.route('/gdisconnect')
def gdisconnect():
	access_token = login_session.get('access_token')

	if access_token is None:
		response = make_response(json.dumps('Current user not connected.'), 401)
		response.headers['Content-Type'] = 'application/json'
		return response

	url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
	h = httplib2.Http()
	result = h.request(url, 'GET')[0]

	if result['status'] != '200':
	    response = make_response(json.dumps('Failed to revoke token for given user.'), 400)
	    response.headers['Content-Type'] = 'application/json'
	    return response

@app.route('/catalog/JSON')
def showCategoriesJSON():
	categories = session.query(Category).all()
	return jsonify(categories = [category.serialize for category in categories])

@app.route('/catalog/<int:catalog_id>/JSON')
@app.route('/catalog/<int:catalog_id>/items/JSON')
def showCategoryJSON(catalog_id):
	categoryItems = session.query(CategoryItem).filter_by(category_id = catalog_id).all()
	return jsonify(categoryItems = [categoryItem.serialize for categoryItem in categoryItems])

@app.route('/catalog/<int:catalog_id>/items/<int:item_id>/JSON')
def showCategoryItemJSON(catalog_id, item_id):
	categoryItem = session.query(CategoryItem).filter_by(id = item_id).first()
	return jsonify(categoryItem = [categoryItem.serialize])

if __name__ == '__main__':
	app.debug = True
	app.secret_key = 'super_secret_key'
	app.run(host = 'localhost', port = 5000)