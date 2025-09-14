import requests
from app import app, db
from models import CovidStat

API_URL = "https://api.covid19api.com/summary"

def fetch_and_store_covid_data():
    try:
        response = requests.get(API_URL)
        response.raise_for_status()
        data = response.json()


        if "Countries" not in data:
            raise ValueError("Invalid API response: 'Countries' key missing")

        countries = data["Countries"]

        with app.app_context():
            for entry in countries:
                country = entry.get("Country")
                confirmed = entry.get("TotalConfirmed")
                deaths = entry.get("TotalDeaths")
                recovered = entry.get("TotalRecovered")

                if not country or confirmed is None or deaths is None:
                    print(f"Skipping invalid entry: {entry}")
                    continue

                stat = CovidStat(
                    country=country,
                    confirmed=confirmed,
                    deaths=deaths,
                    recovered=recovered
                )
                db.session.add(stat)

            db.session.commit()
            print("COVID data successfully stored in database.")

    except Exception as e:
        print(f"Error fetching/storing COVID data: {e}")


if __name__ == "__main__":
    fetch_and_store_covid_data()
