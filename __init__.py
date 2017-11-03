from flask import Flask, jsonify,render_template, request, redirect, jsonify, url_for, flash
from flask import session as login_session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_initialize import Base, Category, CategoryItem, User
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

CLIENT_ID = json.loads(open(path+'/client_secrets.json', 'r').read())['web']['client_id']

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
@app.route('/catalog/')
def showCategories():
	categories = session.query(Category).all()
	categoryItems = session.query(CategoryItem).all()
	return render_template('categories.html', categories = categories, categoryItems = categoryItems, login_session = login_session )

@app.route('/catalog/<int:catalog_id>')
@app.route('/catalog/<int:catalog_id>/items')
def showCategory(catalog_id):
	categories = session.query(Category).all()
	category = session.query(Category).filter_by(id = catalog_id).first()
	categoryName = category.name
	categoryItems = session.query(CategoryItem).filter_by(category_id = catalog_id).all()
	categoryItemsCount = session.query(CategoryItem).filter_by(category_id = catalog_id).count()
	return render_template('category.html', categories = categories, categoryItems = categoryItems, categoryName = categoryName, categoryItemsCount = categoryItemsCount, login_session = login_session )

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

	return render_template('login.html', STATE=state,login_session = login_session)

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
	print 'received state of %s' % request.args.get('state')
    print 'login_sesion["state"] = %s' % login_session['state']
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    gplus_id = request.args.get('gplus_id')
    print "request.args.get('gplus_id') = %s" % request.args.get('gplus_id')
    code = request.data
    print "received code of %s " % code

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets(path+'/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
        
    except FlowExchangeError:
        response = make_response(json.dumps(
            'Failed to upgrade the authorization code.'
            ), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    credentials = credentials.to_json()            
    credentials = json.loads(credentials)         
    access_token = credentials['token_response']['access_token']     
    url = (
        'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
        % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials['id_token']['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'
            ), 200)
        response.headers['Content-Type'] = 'application/json'

    # Store the access token in the session for later use.
    login_session['provider'] = 'google'
    response = make_response(json.dumps('Successfully connected user.', 200))

    print "#Get user info"
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials['token_response']['access_token'], 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    login_session['credentials'] = credentials
    login_session['gplus_id'] = gplus_id
    login_session['username'] = data["name"]
    login_session['picture'] = data["picture"]
    login_session['email'] = data["email"]
    print login_session['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    # dimensions of the picture at login:
    output += ' " style = "width: 300px; height: \
        300px;border-radius: \
        50px;-webkit-border-radius: \
        150px;-moz-border-radius: 50px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output

@app.route('/gdisconnect')
def gdisconnect():
	credentials = login_session.get('credentials')
    # Only disconnect a connected user.
    if not checkLogin(login_session):
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials['token_response']['access_token']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        # Reset the user's session.
        del login_session['credentials']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']

        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash('Successfully disconnected.')
        return redirect(url_for('showCategory'))
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(json.dumps(
            'Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        flash('Failed to revoke token for given user.')
        return redirect(url_for('showCategory'))


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