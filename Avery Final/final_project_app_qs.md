# SI 364 - Final Project questions

## Overall

* **What's a one-two sentence description of what your app will do?**

My app is going to count how many times a certain hashtag (that the user inputs) has been used.

## The Data

* **What data will your app use? From where will you get it? (e.g. scraping a site? what site? -- careful not to run it too much. An API? Which API?)**

My app will use the Twitter API.

* **What data will a user need to enter into a form?**

The user will need to enter their Twitter username, email and a a hashtag of ther choosing.

* **How many fields will your form have? What's an example of some data user might enter into it?**

The form will have three fields. One example of data that the user might choose to enter is the hashtag 'goblue'.

* **After a user enters data into the form, what happens? Does that data help a user search for more data? Does that data get saved in a database? Does that determine what already-saved data the user should see?**

After the user enters all the required data into the form, the app will use the Twitter API to search for the entered hashtag and then email the user the number of times that hashtag has been used. The app will save the hashtags the user searches in a database. 

* **What models will you have in your application?**

Hashtags, users, tweets and emails will be the models used in my application.

* **What fields will each model have?**

The hashtags field will have id and text. Users will have id, twitter_username and email. Tweets will have id, text, user_id and hashtags. Email will have id, text, hashtags and twitter_username.

* **What uniqueness constraints will there be on each table? (e.g. can't add a song with the same title as an existing song)**

One constraint will be that users can't add a hastag to the table that has already been used.

COME BACK

* **What relationships will exist between the tables? What's a 1:many relationship between? What about a many:many relationship?**

A 1:many relationship that will exist will be your username to tweets. A many:many relationship will be twwets to hashtags.

* **How many get_or_create functions will you need? In what order will you invoke them? Which one will need to invoke at least one of the others?**

There will be one instance of a get_or_create function. 

## The Pages

* **How many pages (routes) will your application have?**

There will be one page for the application, the initial form screen.

* **How many different views will a user be able to see, NOT counting errors?**

There will be two views that the user will be able to see. The home form screen and some type of action complete screen.

* **Basically, what will a user see on each page / at each route? Will it change depending on something else -- e.g. they see a form if they haven't submitted anything, but they see a list of things if they have?**

The first page will be where the user will input the required data. After they click submit they will be taken to a second route that has some type of message telling them their action is complete and to check their email. 

## Extras

* **Why might your application send email?**

I chose for my application to send an eamil to the user because I wanted to utilize this new skill we have learned recently.

* **If you plan to have user accounts, what information will be specific to a user account? What can you only see if you're logged in? What will you see if you're not logged in -- anything?**

* **What are your biggest concerns about the process of building this application?**

I'm a little worried my idea is too simple and will not meet all the requirements but am struggling to find ways to make it a little more complex without making it too hard for myself to complete. 
