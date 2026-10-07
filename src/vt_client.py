import os
import logging
import requests
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

VT_API_KEY = os.getenv("VT_API_KEY", "")

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def enrich_indicator(indicator_type, value):

    if not VT_API_KEY:
        logger.error("VirusTotal API key not configured")

        return {
            "indicator": value,
            "type": indicator_type,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "status": "NO_API_KEY"
        }

    headers = {
        "x-apikey": VT_API_KEY
    }

    try:

        if indicator_type == "ip":
            endpoint = f"{VT_BASE_URL}/ip_addresses/{value}"

        elif indicator_type == "domain":
            endpoint = f"{VT_BASE_URL}/domains/{value}"

        elif indicator_type == "url":
            logger.warning(
                "URL enrichment requires URL-specific handling"
            )

            return {
                "indicator": value,
                "type": indicator_type,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "status": "UNSUPPORTED"
            }

        elif indicator_type == "hash":
            endpoint = f"{VT_BASE_URL}/files/{value}"

        else:
            logger.warning(
                "Unsupported indicator type: %s",
                indicator_type
            )

            return {
                "indicator": value,
                "type": indicator_type,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "status": "UNSUPPORTED"
            }

        response = requests.get(
            endpoint,
            headers=headers,
            timeout=10
        )

        # -----------------------------
        # INVALID API KEY
        # -----------------------------

        if response.status_code == 401:

            logger.error(
                "VirusTotal API key is invalid or unauthorized"
            )

            return {
                "indicator": value,
                "type": indicator_type,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "status": "INVALID_API_KEY"
            }

        # -----------------------------
        # FORBIDDEN
        # -----------------------------

        if response.status_code == 403:

            logger.error(
                "VirusTotal API access forbidden"
            )

            return {
                "indicator": value,
                "type": indicator_type,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "status": "FORBIDDEN"
            }

        # -----------------------------
        # RATE LIMIT
        # -----------------------------

        if response.status_code == 429:

            logger.warning(
                "VirusTotal API rate limit exceeded"
            )

            return {
                "indicator": value,
                "type": indicator_type,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "status": "RATE_LIMITED"
            }

        # -----------------------------
        # OTHER HTTP ERRORS
        # -----------------------------

        if response.status_code >= 400:

            logger.error(
                "VirusTotal HTTP error: %s",
                response.status_code
            )

            return {
                "indicator": value,
                "type": indicator_type,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "undetected": 0,
                "status": f"HTTP_ERROR_{response.status_code}"
            }

        # -----------------------------
        # SUCCESS
        # -----------------------------

        data = response.json()

        stats = (
            data
            .get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )

        return {
            "indicator": value,
            "type": indicator_type,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "status": "OK"
        }

    # -----------------------------
    # TIMEOUT
    # -----------------------------

    except requests.Timeout:

        logger.error(
            "VirusTotal request timed out"
        )

        return {
            "indicator": value,
            "type": indicator_type,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "status": "TIMEOUT"
        }

    # -----------------------------
    # NETWORK ERROR
    # -----------------------------

    except requests.ConnectionError as error:

        logger.error(
            "VirusTotal connection error: %s",
            error
        )

        return {
            "indicator": value,
            "type": indicator_type,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "status": "CONNECTION_ERROR"
        }

    # -----------------------------
    # INVALID JSON
    # -----------------------------

    except ValueError:

        logger.error(
            "VirusTotal returned invalid JSON"
        )

        return {
            "indicator": value,
            "type": indicator_type,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "status": "INVALID_RESPONSE"
        }

    # -----------------------------
    # UNEXPECTED ERROR
    # -----------------------------

    except Exception as error:

        logger.exception(
            "Unexpected VirusTotal error: %s",
            error
        )

        return {
            "indicator": value,
            "type": indicator_type,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "status": "ERROR"
        }
