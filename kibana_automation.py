from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
import time
import os
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('kibana_report.log'),
        logging.StreamHandler()
    ]
)

# Configuration
BASE_URL = "https://10.212.55.87"
DOWNLOAD_DIR = r"C:\Users\vansh\Downloads"  # Change to your download directory
WAIT_TIMEOUT = 60

def setup_driver():
    chrome_options = Options()
    # chrome_options.add_argument("--headless")  # Disabled for debugging
    chrome_options.add_experimental_option("prefs", {
        "download.default_directory": DOWNLOAD_DIR,
        "download.prompt_for_download": False,
    })
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    return webdriver.Chrome(options=chrome_options)

def save_debug_info(driver, context):
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    debug_dir = "debug_logs"
    os.makedirs(debug_dir, exist_ok=True)
    
    with open(f"{debug_dir}/page_{timestamp}_{context}.html", "w", encoding="utf-8") as f:
        f.write(driver.page_source)
    driver.save_screenshot(f"{debug_dir}/screenshot_{timestamp}_{context}.png")
    logging.info(f"Saved debug info for {context}")

def main():
    driver = setup_driver()
    try:
        # Step 1: Navigate to Discover page
        logging.info("Loading Discover page...")
        discover_url = f"{BASE_URL}/app/discover#/?_a=(columns:!(),filters:!(),index:'63d108a0-fc9e-11ee-8ba9-b178c8b3dc57',interval:auto,query:(language:kuery,query:''),sort:!(!('@timestamp',desc)))"
        driver.get(discover_url)
        
        # Step 2: Click Share button
        try:
            share_button = WebDriverWait(driver, WAIT_TIMEOUT).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "[data-test-subj='shareTopNavButton']")))
            share_button.click()
            logging.info("Clicked Share button")
        except TimeoutException:
            save_debug_info(driver, "share_button_timeout")
            raise

        # Step 3: Select CSV Report
        try:
            csv_option = WebDriverWait(driver, WAIT_TIMEOUT).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "[data-test-subj='sharePanel-CSVReports']")))
            csv_option.click()
            logging.info("Selected CSV option")
        except TimeoutException:
            save_debug_info(driver, "csv_option_timeout")
            raise

        # Step 4: Generate Report
        try:
            generate_button = WebDriverWait(driver, WAIT_TIMEOUT).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "[data-test-subj='generateReportButton']")))
            generate_button.click()
            logging.info("Report generation started...")
        except TimeoutException:
            save_debug_info(driver, "generate_button_timeout")
            raise

        # Step 5: Wait for report generation
        logging.info("Waiting for report generation (up to 3 minutes)...")
        time.sleep(180)  # Increased wait time for large reports

        # Step 6: Navigate to Reporting page
        driver.get(f"{BASE_URL}/app/management/insightsAndAlerting/reporting")
        logging.info("Loading Reports page...")

        # Step 7: Download the most recent report - NEW SELECTOR
        try:
            logging.info("Locating newest report...")
            # Wait for table to load
            WebDriverWait(driver, WAIT_TIMEOUT).until(
                EC.presence_of_element_located((By.CSS_SELECTOR, "[data-test-subj='reportJobRow']")))
            
            # Find the first download button in the table
            download_button = WebDriverWait(driver, WAIT_TIMEOUT).until(
                EC.element_to_be_clickable((By.CSS_SELECTOR, "[data-test-subj='reportJobRow'] [aria-label='Download report']")))
            download_button.click()
            logging.info("Download initiated")
        except TimeoutException:
            save_debug_info(driver, "download_button_timeout")
            raise

        # Wait for download to complete
        time.sleep(20)
        
        # Verify download
        files = [f for f in os.listdir(DOWNLOAD_DIR) if f.endswith('.csv')]
        if files:
            newest_file = max([os.path.join(DOWNLOAD_DIR, f) for f in files], key=os.path.getctime)
            logging.info(f"Download complete: {newest_file}")
        else:
            logging.warning("No CSV file found in downloads directory")

    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        save_debug_info(driver, "final_error")
        raise
    finally:
        driver.quit()
        logging.info("Browser closed")

if __name__ == "__main__":
    main()