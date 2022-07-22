# Authentication and Security

This project follows instructions from the [Complete Web Development Bootcamp](https://www.udemy.com/course/the-complete-web-development-bootcamp). Throughout the course about authentication and security it is covered all 6 available levels:
- Register user with username and password
- Database encryption
- Hashin passwords
- Salting and Hashin passwords
- Cookies and Sessions
- Oauth with Google

This project covers only the last 2 options, other 4 were overwritten.

---
## Requirements
- Node 16
- Git
- MongoDB Shell

---
## Common setup
Clone the repo and install the dependencies.
``` 
git clone https://github.com/ana-gujabidze/Secrets_Nodejs.git
cd Secrets_Nodejs
```
``` 
npm install
```
Users in the app are being authenticatied with Google using the OAuth 2.0 API. In order to achieve this and run this app successfully, first register an application with Google, follow this [link](https://console.developers.google.com/). Your application will be issued a client ID and client secret, which should be added to `.env` file. Create `.env` file similar to `.env_sample` file and specify all environmental variables.

---

## Run locally

In the CLI run the following command to run the primary daemon process for the MongoDB system
```
mongod
```
In another tab run this command to connect to local MongoDB
```
mongo
```
In the third tab of the CLI run the command
```
nodemon app.js
```
Open the browser and follow the link 
```
http://localhost:3000/
```