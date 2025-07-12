# WOOFER
#### https://woofer-rsb9.onrender.com/
#### Video Demo:  https://www.youtube.com/watch?v=ExM4j3fED9s
#### Description:

WOOFER is a social media (Twitter) clone WebApp. It is made using
Flask, along with HTML,CSS (and Bootstrap), and JavaScript.

It allows users to create account, login and post WOOFS (tweets,
text-only).

All data is stored in a SQL database (woofer.db) using sqlite.
There are two tables in the database, one containing user data,
and the other containing Woof data (content, OP, timestamp).

All the validation has been done server-side to ensure that only
correct data reaches the database.

All the front end web pages have been designed using Bootstrap 5.
If the user is not logged in, user is redirected to '/login'
route, where he can log in or go to '/register' to register a
new user ("Create New Account" button).

Homepage or "index.html" provides access to all the woofs (tweets)
made in the platform (latest-first) and provides a way to make a
woof.

My Woofs page displays all the woofs made by the current user
(latest-first).

Profile page displays the Name, Username, and Number of Woofs
made by the user. It also provides a way to change the user's
password.

Log out tab clears the session and logs the user out.

The inspiration of the design of this WebApp is taken from Twitter and Facebook. The name Woofer is inspired by Twitter, but the twitter birf is swapped with a dog paw. All the front-end design in this app is done using Bootstrap 5. This includes the login form, register from, page layouts, nav bar, etc. The inspiration for the colour scheme is taken from Color Hunt (www.colorhunt.co). Server side validation is implemented instead of client side verification to ensure that only allowed data is entered in the database. Passwords created have to be atleast 8 characters long, with atleast one lowercase letter ,atleast one uppercase letter, atleast one number, and atleast one symbol from from _ or @ or $.

As it is a very basic social media clone with only text 'woofs', only two tables are made in the database:- users table to store user details like name, username, email, userid, etc., and woofs table to store the content of the woof, orignal poster, and timestamp of when the woof was made. Woofs are display according to this timestamp, latest first.

Ideas that may be implemented at a later time:-
-> There are extra columns availible in the users table for followers and following, like that in twitter and instagram, which records the number of users followed by and following the user. An additional table is to be made to record all these interactions.
-> The ability to like and comment a woof can be implemented. For this the woof table has to be expanded and seperate tables for likes and comments be made.
-> If the ability to like or comment is implemented, the problem occuring during simultaneus likes and comments (only one is recorded at a time) has to be dealt with.
-> The ability to post photos can be implemented.
-> Only a particular ammount of woofs should be loaded at a time and rest loaded after scrolling to reduce load on server.
-> Email verification can be implemented while creating accounts.