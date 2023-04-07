# Lt-Colonel-Kilgore-team web crawler
## Project description 
This project consists of a web crawler that scrapes websites and stores the results in a Postgres database. The project has two main components:

1. Database Setup directory ('DatabaseSetup'): This directory contains a docker-compose file for setting up the Postgres database.   
2. Web Crawler script ('WebCrawlerService.py'): This Python script is responsible for the web crawling process.

### Features

- Concurrent scraping using multithreading
- Support for handling robot.txt and sitemap.xml files
- Storage of data in a PostgreSQL database
- Duplicate page detection and handling
- SQLite database for managing crawl frontier and crawl delays

## Necessary programs
- Docker (if on Windows, install docker desktop)
- Docker Compose 
- Postman 
- IDE (PyCharm/VsCode) 
- Python (3 and up)
### Optional programs
- pgAdmin
- DB Browser for SQLite
## Set up the postgres database

In the DatabaseSetup directory, open a terminal (e.g., PowerShell on Windows) and run the following command:
```Shell
docker compose up -d
```
This command will create the PostgreSQL database using the schema provided in the init-schema file.

## Starting the web crawler
1. Open the project in your preferred IDE (e.g., PyCharm or VSCode).
2. Install the required dependencies by running pip install -r requirements.txt.
3. In the WebCrawlerService.py script, you can set the number of threads you want to run in the main function by adjusting the max_workers parameter (e.g., max_workers=10).
4. Run the program using the IDE's run button or use the command flask --app sample --debug run.
5. To startthe web crawler, send a POST request to the /scrape endpoint using Postman with the following JSON format:
Example:
```JSON
    {
  "messages": [
            "https://www.gov.si/",
            "https://evem.gov.si/",
            "https://e-uprava.gov.si/",
            "https://www.e-prostor.gov.si/"
  ]
}
```
This will initiate the web scraping process for the specified websites, and the results will be stored in the PostgreSQL database.




