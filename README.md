Udacity FSND Item Catalog project
In this project, I build up a web application that showed several items and catalogries with descriptions.
Authenticated users who sign up through google accound can add, edit and delete items they want.
To run the project code, you need to do following things:
1. Set up a virtual machine provided by Udacity:
   https://github.com/udacity/fullstack-nanodegree-vm
2. Copy the project folder into the vagrant folder and in the virtual machin, use "cd" command to change directory to the project folder in the vagrant folder
3. Use "python database_initialize.py" command to initialize the database.
4. Use "python demoItems.py" command to create some demo data into the database, instead of an empty database
5. Use "python itemCatalogApp.py" command to run the web app
6. In your browser, use URL "http://local:5000/" to navigate into this web app.
7. In the app, use your google account to login and there will be an add item button show up in the homepage.