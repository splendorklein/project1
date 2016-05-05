from flask import Flask, render_template, request, redirect, jsonify, url_for, flash, Response
from sqlalchemy import create_engine, asc, func
from sqlalchemy.orm import sessionmaker
from database_setup import Categories, Base, Items, User, ContactInfo
from databaseminingbase import RealEstate
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from datetime import timedelta
import time
import sys
import math
from Queue import Queue
from sklearn import preprocessing
from sklearn import svm
import numpy as np


app = Flask(__name__)


CLIENT_ID = json.loads(
    open('////var/www/mywebsite/mywebsite/client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"
q = Queue()

def point_distance(x1, y1, x2, y2):
    return ((x1-x2)**2.0 + (y1-y2)**2.0)**(0.5)

def remap(value, min1, max1, min2, max2):
    return float(min2) + (float(value) - float(min1)) * (float(max2) - float(min2)) / (float(max1) - float(min1))

def normalizeArray(inputArray):
    maxVal = 0
    minVal = 100000000000

    for j in range(len(inputArray)):
        for i in range(len(inputArray[j])):
            if inputArray[j][i] > maxVal:
                maxVal = inputArray[j][i]
            if inputArray[j][i] < minVal:
                minVal = inputArray[j][i]

    for j in range(len(inputArray)):
        for i in range(len(inputArray[j])):
            inputArray[j][i] = remap(inputArray[j][i], minVal, maxVal, 0, 1)

    return inputArray

def event_stream():
    while True:
        result = q.get()
        yield 'data: %s\n\n' % str(result)


@app.before_request
def make_session_permanent():
    login_session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=5)

# Connect to Database and create database session
def connect():    
    engine = create_engine('sqlite:////var/www/mywebsite/mywebsite/database/catalog.db')
    Base.metadata.bind = engine

    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    return session
def connectdata():    
    engine = create_engine('sqlite:////var/www/mywebsite/mywebsite/database/datamining.db')
    Base.metadata.bind = engine

    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    return session
@app.route('/eventSource/')
def sse_source():
    return Response(
            event_stream(),
            mimetype='text/event-stream')

@app.route("/project1")
def index():
    return render_template("index.html")

@app.route("/getData/")
def getData():

    q.put("starting data query...")

    lat1 = str(request.args.get('lat1'))
    lng1 = str(request.args.get('lng1'))
    lat2 = str(request.args.get('lat2'))
    lng2 = str(request.args.get('lng2'))

    w = float(request.args.get('w'))
    h = float(request.args.get('h'))
    cell_size = float(request.args.get('cell_size'))

    analysis = request.args.get('analysis')
    heatmap = request.args.get('heatmap')
    spread = request.args.get('spread')
    if spread == "":
        spread = 12
    else:
        try:
            spread = int(spread)
        except:

            spread = 12
    #CAPTURE ANY ADDITIONAL ARGUMENTS SENT FROM THE CLIENT HERE

    engine = create_engine('sqlite:////var/www/mywebsite/mywebsite/database/datamining.db')
    Base.metadata.bind = engine

    DBSession = sessionmaker(bind=engine)
    session = DBSession()
    records = session.query(RealEstate).filter(RealEstate.latitude>lat1, RealEstate.latitude<lat2, 
        RealEstate.longitude>lng1, RealEstate.longitude<lng2).all()

    #USE INFORMATION RECEIVED FROM CLIENT TO CONTROL 
    #HOW MANY RECORDS ARE CONSIDERED IN THE ANALYSIS
    if heatmap == "true":
        random.shuffle(records)
        records = records[:100]

    numListings = len(records)


    # iterate through data to find minimum and maximum price
    minPrice = 1000000000
    maxPrice = 0

    for record in records:
        price = record.price

        if price > maxPrice:
            maxPrice = price
        if price < minPrice:
            minPrice = price

    output = {"type":"FeatureCollection","features":[]}

    for record in records:
        feature = {"type":"Feature","properties":{},"geometry":{"type":"Point"}}
        feature["id"] = record.id
        feature["properties"]["name"] = record.title
        feature["properties"]["price"] = record.price
        feature["properties"]["priceNorm"] = remap(record.price, minPrice, maxPrice, 0, 1)
        feature["geometry"]["coordinates"] = [record.latitude, record.longitude]

        output["features"].append(feature)

    if heatmap == "false":
        if analysis == "false":
            q.put('idle')
            return json.dumps(output)

    

    output["analysis"] = []

    numW = int(math.floor(w/cell_size))
    numH = int(math.floor(h/cell_size))

    grid = []

    for j in range(numH):
        grid.append([])
        for i in range(numW):
            grid[j].append(0)

    #USE CONDITIONAL ALONG WITH UI INFORMATION RECEIVED FROM THE CLIENT TO SWITCH
    #BETWEEN HEAT MAP AND INTERPOLATION ANALYSIS
    if heatmap == "true":
    ## HEAT MAP IMPLEMENTATION
        q.put('starting heatmap analysis...')
        for record in records:

            pos_x = int(remap(record.longitude, lng1, lng2, 0, numW))
            pos_y = int(remap(record.latitude, lat1, lat2, numH, 0))

    #USE INFORMATION RECEIVED FROM CLIENT TO CONTROL SPREAD OF HEAT MAP
            #spread = 12
            if ((spread>0)and(spread<20)):
                spread = spread
            else :
                spread = 12
                print "spread = defult value"

            for j in range(max(0, (pos_y-spread)), min(numH, (pos_y+spread))):
                for i in range(max(0, (pos_x-spread)), min(numW, (pos_x+spread))):
                    grid[j][i] += 2 * math.exp((-point_distance(i,j,pos_x,pos_y)**2)/(2*(spread/2)**2))
        grid = normalizeArray(grid)

        offsetLeft = (w - numW * cell_size) / 2.0
        offsetTop = (h - numH * cell_size) / 2.0

        for j in range(numH):
            for i in range(numW):
                newItem = {}

                newItem['x'] = offsetLeft + i*cell_size
                newItem['y'] = offsetTop + j*cell_size
                newItem['width'] = cell_size-1
                newItem['height'] = cell_size-1
                newItem['value'] = grid[j][i]

                output["analysis"].append(newItem)
        if analysis == "false":
            q.put('idle')
        if analysis == "true":
            q.put('cannot run both, run as heatmap')
        return json.dumps(output)


    ## MACHINE LEARNING IMPLEMENTATION
    if ((heatmap == "false") and (analysis == "true")):
        q.put('starting interpolation analysis...')
        featureData = []
        targetData = []

        for record in records:
            featureData.append([record.latitude, record.longitude])
            targetData.append(record.price)

        X = np.asarray(featureData, dtype='float')
        y = np.asarray(targetData, dtype='float')

        breakpoint = int(numListings * .7)



    # create training and validation set
        X_train = X[:breakpoint]
        X_val = X[breakpoint:]

        y_train = y[:breakpoint]
        y_val = y[breakpoint:]

    #mean 0, variance 1
        scaler = preprocessing.StandardScaler().fit(X_train)
        X_train_scaled = scaler.transform(X_train)

        mse_min = 10000000000000000000000

        for C in [.01, 1, 100, 10000, 1000000]:

            for e in [.01, 1, 100, 10000, 1000000]:

                    for g in [.01, 1, 100, 10000, 1000000]:

                        q.put("training model: C[" + str(C) + "], e[" + str(e) + "], g[" + str(g) + "]")

                        model = svm.SVR(C=C, epsilon=e, gamma=g, kernel='rbf', cache_size=2000)
                        model.fit(X_train_scaled, y_train)

                        y_val_p = [model.predict(i) for i in X_val]

                        mse = 0
                        for i in range(len(y_val_p)):
                            mse += (y_val_p[i] - y_val[i]) ** 2
                        mse /= len(y_val_p)

                        if mse < mse_min:
                            mse_min = mse
                            model_best = model
                            C_best = C
                            e_best = e
                            g_best = g

        q.put("best model: C[" + str(C_best) + "], e[" + str(e_best) + "], g[" + str(g_best) + "]")

        for j in range(numH):
            for i in range(numW):
                lat = remap(j, numH, 0, lat1, lat2)
                lng = remap(i, 0, numW, lng1, lng2)

                testData = [[lat, lng]]
                X_test = np.asarray(testData, dtype='float')
                X_test_scaled = scaler.transform(X_test)
                grid[j][i] = model_best.predict(X_test_scaled)
        grid = normalizeArray(grid)

        offsetLeft = (w - numW * cell_size) / 2.0
        offsetTop = (h - numH * cell_size) / 2.0

        for j in range(numH):
            for i in range(numW):
                newItem = {}

                newItem['x'] = offsetLeft + i*cell_size
                newItem['y'] = offsetTop + j*cell_size
                newItem['width'] = cell_size-1
                newItem['height'] = cell_size-1
                newItem['value'] = grid[j][i]

                output["analysis"].append(newItem)

        q.put('idle')

        return json.dumps(output)


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('////var/www/mywebsite/mywebsite/fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('/var/www/mywebsite/mywebsite/fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]


    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout, let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"



@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('////var/www/mywebsite/mywebsite/client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        print '500 error'
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
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
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'
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
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output



def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session = connect()
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    
    return user.id


def getUserInfo(user_id):
    session = connect()
    user = session.query(User).filter_by(id=user_id).one()
    
    return user


def getUserID(email):
    try:
        session = connect()
        user = session.query(User).filter_by(email=email).one()
        
        return user.id
    except:
        return None
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/catalog.json')
def categoriesJSON():
    session = connect()
    items = session.query(Items).all()
    
    return jsonify(categories=[i.serialize for i in items])


# Show all restaurants
@app.route('/', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':


            if request.form['name'] == '' or request.form['name'] == 'Enter your name here...':
                flash('Name can not be empty!')
            elif request.form['email'] == '' or request.form['email'] == 'Enter your email here...':
                flash('Email can not be empty!')
            elif request.form['messagetolinmao'] == '' or request.form['messagetolinmao'] == 'Enter your message here...':
                flash('Please leave you message!')
            else:
                try:
                    session = connect()
                    newContact = ContactInfo(name=request.form['name'], email=request.form['email'], message=request.form['messagetolinmao'])

                    session.add(newContact)
                    session.commit()
                    flash('Successfully Sent Your Message to Linmao!')
                except:
                    flash('Failed!')

            return redirect(url_for('contact'))
    else:

        return render_template('info.html')

@app.route('/linmao/cong/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        try:
            if request.form['password'] == 'this is a tasted burger':

                session = connect()

                users = session.query(User)
                cons = session.query(ContactInfo)
                return render_template('database.html', users = users, cons = cons)

            else:
                flash('WRONG!')
                return render_template('admin.html')
        except:
            flash('fail')
            return redirect(url_for('admin'))

    else:
        return render_template('admin.html')

@app.route('/newpage/test')
def index():
    return render_template('main.html')

@app.route('/catalog')
def showCatalog():
    session = connect()
    categories = session.query(Categories)  #.order_by(asc(Restaurant.name))
    items = session.query(Items).order_by(Items.id.desc()).limit(10)
    
    if 'username' not in login_session:
        return render_template('categories.html', categories=categories, items = items)
    else:    
        return render_template('categorieslogged.html', categories=categories, items = items)


@app.route('/catalog/<string:categories_name>')
@app.route('/catalog/<string:categories_name>/items')
def showitems(categories_name):
    session = connect()
    categories = session.query(Categories)  
    cat = session.query(Categories).filter_by(name=categories_name).one()
    items = session.query(Items).filter_by(category_name=categories_name).all()
    count = len(items)
    
    if False:
        return render_template('items.html', categories=categories, items = items,
        cat = cat,count=count)
    else:
        return render_template('itemslogged.html', categories=categories, items = items,
        cat = cat,count=count)


@app.route('/catalog/<string:categories_name>/<string:items_name>')
def showdescription(categories_name,items_name):
    session = connect()
    items = session.query(Items).filter_by(category_name=categories_name, name=items_name).one()
    
    if (items == []):
        return 'item not found'
    elif 'username' not in login_session: 
        
        return render_template('description.html', items = items)
    else:
        return render_template('descriptionlogged.html', items = items)


# Create a new item
@app.route('/catalog/<string:categories_name>/new', methods=['GET', 'POST'])
def newItem(categories_name):
    if 'username' not in login_session:
        return redirect('/login')
    try:
        session = connect()
        categories = session.query(Categories).filter_by(name=categories_name).one()
    except:
        
        return 'category name does not exist!'

    if request.method == 'POST':
        try:
            findItme= session.query(Items).filter_by(
                category_name=categories_name, name=request.form['name']).one()
            
            return 'Name already exists!'
        except:

            if request.form['name'] == '':
                flash('Name can not be empty!')

            else:
                newItem = Items(name=request.form['name'], description=request.form[
                                   'description'],categories_name = categories)
                session.add(newItem)
                session.commit()
                flash('New %s Item Successfully Created' % (newItem.name))
                    
        return redirect(url_for('showitems', categories_name=categories_name))
    else:
        
        return render_template('newitem.html', categories_name=categories_name)

# Edit a menu item


@app.route('/catalog/<string:categories_name>/<string:items_name>/edit', methods=['GET', 'POST'])
def editItem(categories_name, items_name):
    if 'username' not in login_session:
        return redirect('/login')
    session = connect()
    editedItem = session.query(Items).filter_by(name=items_name).one()
    categories = session.query(Categories).filter_by(name=categories_name).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category']:
            editedItem.category_name = request.form['category']            

        session.add(editedItem)
        session.commit()
        flash('Menu Item Successfully Edited')
        
        return redirect(url_for('showitems', categories_name=categories_name))
    else:
        
        return render_template('edititem.html', 
            categories_name=categories_name, items_name=items_name, item=editedItem)


# Delete a menu item
@app.route('/catalog/<string:categories_name>/<string:items_name>/delete', methods=['GET', 'POST'])
def deleteItem(categories_name, items_name):
    if 'username' not in login_session:
        return redirect('/login')
    session = connect()
    categories = session.query(Categories).filter_by(name=categories_name).one()
    itemToDelete = session.query(Items).filter_by(name=items_name).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        
        return redirect(url_for('showitems', categories_name=categories_name))
    else:
        
        return render_template('deleteItem.html', item=itemToDelete)


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run()
