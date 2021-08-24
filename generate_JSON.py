import sys
import website_fetcher


# Get JSON files for the domains predicted as phishing (both true positives and false positives) by the model

# # Generate JSON files and screenshots
# f = open("/var/tmp/phishing/benign_train.txt", "r")
# while True:
#     url = f.readline().strip()
#     if not url:
#         break
#     print(url)
#     fetcher = website_fetcher.WebsiteFetcher(confirm=True)
#     fetcher.fetch_and_save_data(url)
# f.close()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Please include the path to the text file containing training domains.")
        exit(0)
    else:
        train_path = sys.argv[1]
        # Generate JSON files and screenshots
        f = open(train_path, "r")
        while True:
            url = f.readline().strip()
            if not url:
                break
            print(url)
            fetcher = website_fetcher.WebsiteFetcher(confirm=True)
            fetcher.fetch_and_save_data(url)
        f.close()

