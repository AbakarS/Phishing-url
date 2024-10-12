"""
This module provides a class for extracting features from URLs to detect phishing attempts.

The PhishingURLExtract class processes a dataset of URLs and extracts various features, 
such as URL length, presence of IP addresses, number of subdomains, and special characters. 
These features can be used to train machine learning models for phishing detection or other 
forms of analysis.

Usage example:
    analyzer = PhishingURLExtract("data.csv")
    analyzer.extract_features()
    analyzer.save_to_csv("features.csv")
"""

import re
from urllib.parse import urlparse
import tldextract
import pandas as pd

class PhishingURLExtract:
    """
    A class to extract features from URLs for phishing detection.
    
    This class provides methods to analyze various components of URLs, such as length, 
    presence of IP, number of subdomains, specific characters, and more, to aid in detecting 
    phishing URLs.
    
    Attributes:
        df (pd.DataFrame): The dataframe that stores the URLs and their extracted features.
    """
 
    def __init__(self, path):
        self.df = self.data_import(path)

    def data_import(self, path):
        """Import data from a CSV file."""
        return pd.read_csv(path)

    def url_length(self, url):
        """Return the length of the URL."""
        return len(url)

    def has_ip(self, url):
        """Check if the URL contains an IP address."""
        return 1 if re.search(r"\d+\.\d+\.\d+\.\d+", url) else 0

    def number_subdomains(self, url):
        """Return the number of subdomains in the URL."""
        extracted = tldextract.extract(url)
        return len(extracted.subdomain.split(".")) if extracted.subdomain else 0

    def domain_length(self, url):
        """Return the length of the domain name."""
        extracted = tldextract.extract(url)
        return len(extracted.domain)
    
    def domain_repeat(self, url):
        """Return the number of times the domain is repeated in the URL."""
        extracted = tldextract.extract(url)
        return url.lower().count(extracted.domain.lower())
    
    def protocole_length(self, url):
        """Return the length of the protocol (scheme) in the URL."""
        parsed_url = urlparse(url)
        return len(parsed_url.scheme)
    
    def number_question_marks(self, url):
        """Return the number of question marks (?) in the URL."""
        return url.count("?")
    
    def number_exclamation_marks(self, url):
        """Return the number of exclamation points (!) in the URL."""
        return url.count("!")
    
    def number_at_symbols(self, url):
        """Return the number of @ symbols in the URL."""
        return url.count("@")
    
    def number_hyphens(self, url):
        """Return the number of hyphens (-) in the URL."""
        return url.count("-")
    
    def number_underscore(self, url):
        """Return the number of underscores (_) in the URL."""
        return url.count("_")
    
    def number_equals(self, url):
        """Return the number of equals (=) symbols in the URL."""
        return url.count("=")
    
    def number_slashes(self, url):
        """Return the number of slashes (/) in the URL."""
        return url.count("/")
    
    def number_digits(self, url):
        """Return the number of digits in the URL."""
        return len(re.findall(r"\d", url))
    
    def path_length(self, url):
        """Return the length of the URL path."""
        return len(urlparse(url).path)
    
    def number_dots(self, url):
        """Return the number of dots (.) in the URL."""
        return url.count(".")
    
    def http_in_path_or_subdomain(self, url):
        """Check if 'http' is present in the path or subdomain of the URL."""
        parsed_url = urlparse(url)
        extracted = tldextract.extract(url)
        return 0 if "http" in parsed_url.path.lower() or "http" in extracted.subdomain.lower() else 1
    
    def https_in_path_or_subdomain(self, url):
        """Check if 'https' is present in the path or subdomain of the URL."""
        parsed_url = urlparse(url)
        extracted = tldextract.extract(url)
        return 0 if "https" in parsed_url.path.lower() or "https" in extracted.subdomain.lower() else 1
    
    def query_length(self, url):
        """Return the length of the query string in the URL."""
        parsed_url = urlparse(url)
        return len(parsed_url.query)
    
    def has_port(self, url):
        """Check if a port is specified in the URL."""
        parsed_url = urlparse(url)
        return 0 if parsed_url.port else 1

    def extract_features(self):
        """Extract all features from the URLs and add them to the dataframe."""
        self.df["url_length"] = self.df["URL"].apply(self.url_length)
        self.df["has_ip"] = self.df["URL"].apply(self.has_ip)
        self.df["number_subdomains"] = self.df["URL"].apply(self.number_subdomains)
        self.df["domain_length"] = self.df["URL"].apply(self.domain_length)
        self.df["domain_repeat"] = self.df["URL"].apply(self.domain_repeat)
        self.df["protocole_length"] = self.df["URL"].apply(self.protocole_length)
        self.df["number_question_marks"] = self.df["URL"].apply(self.number_question_marks)
        self.df["number_exclamation_marks"] = self.df["URL"].apply(self.number_exclamation_marks)
        self.df["number_at_symbols"] = self.df["URL"].apply(self.number_at_symbols)
        self.df["number_hyphens"] = self.df["URL"].apply(self.number_hyphens)
        self.df["number_underscore"] = self.df["URL"].apply(self.number_underscore)
        self.df["number_equals"] = self.df["URL"].apply(self.number_equals)
        self.df["number_slashes"] = self.df["URL"].apply(self.number_slashes)
        self.df["number_digits"] = self.df["URL"].apply(self.number_digits)
        self.df["path_length"] = self.df["URL"].apply(self.path_length)
        self.df["number_dots"] = self.df["URL"].apply(self.number_dots)
        self.df["http_in_path_or_subdomain"] = self.df["URL"].apply(self.http_in_path_or_subdomain)
        self.df["https_in_path_or_subdomain"] = self.df["URL"].apply(self.https_in_path_or_subdomain)
        self.df["query_length"] = self.df["URL"].apply(self.query_length)
        self.df["has_port"] = self.df["URL"].apply(self.has_port)

    def save_to_csv(self, output_path):
        """Save the dataframe with the extracted features to a CSV file."""
        self.df.to_csv(output_path, index=False)


# Example usage
if __name__ == "__main__":
    analyzer = PhishingURLExtract("C:/Users/HP/OneDrive/Bureau/phishing_url_analyzer/phishing_url_analyzer/data/data.csv")
    analyzer.extract_features()
    analyzer.save_to_csv("phishing_url_analyzer/features_extracting/featuresextract_df.csv")

    # Limit display to 5 columns
    pd.set_option('display.max_columns', 5)
    print(analyzer.df.head(5))
    print(analyzer.df.info())
