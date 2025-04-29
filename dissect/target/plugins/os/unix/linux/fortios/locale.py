from __future__ import annotations

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import export
from dissect.target.plugins.os.default.locale import LocalePlugin


class FortiOSLocalePlugin(LocalePlugin):
    """FortiOS locale plugin."""

    def check_compatible(self) -> None:
        if self.target.os != "fortios":
            raise UnsupportedPluginError("FortiOS specific plugin loaded on non-FortiOS target")

    @export(property=True)
    def timezone(self) -> str | None:
        """Return configured UI/system timezone."""
        try:
            timezone_num = self.target._os._config["global-config"]["system"]["global"]["timezone"][0]
            return translate_timezone(timezone_num)
        except KeyError:
            pass

    @export(property=True)
    def language(self) -> str | None:
        """Return configured UI language."""
        LANG_MAP = {
            "english": "en_US",
            "french": "fr_FR",
            "spanish": "es_ES",
            "portuguese": "pt_PT",
            "japanese": "ja_JP",
            "trach": "zh_TW",
            "simch": "zh_CN",
            "korean": "ko_KR",
        }
        try:
            lang_str = self.target._os._config["global-config"]["system"]["global"].get("language", ["english"])[0]
            return LANG_MAP.get(lang_str, lang_str)
        except KeyError:
            pass


def translate_timezone(timezone_num: str) -> str:
    """Translate a FortiOS timezone number to IANA TZ.

    Resources:
        - https://<fortios>/ng/system/settings
    """

    TZ_MAP = {
        "01": "Etc/GMT+11",  # (GMT-11:00) Midway Island, Samoa
        "02": "Pacific/Honolulu",  # (GMT-10:00) Hawaii
        "03": "America/Anchorage",  # (GMT-9:00) Alaska
        "04": "America/Los_Angeles",  # (GMT-8:00) Pacific Time (US & Canada)
        "05": "America/Phoenix",  # (GMT-7:00) Arizona
        "81": "America/Chihuahua",  # (GMT-7:00) Baja California Sur, Chihuahua
        "06": "America/Denver",  # (GMT-7:00) Mountain Time (US & Canada)
        "07": "America/Guatemala",  # (GMT-6:00) Central America
        "08": "America/Chicago",  # (GMT-6:00) Central Time (US & Canada)
        "09": "America/Mexico_City",  # (GMT-6:00) Mexico City
        "10": "America/Regina",  # (GMT-6:00) Saskatchewan
        "11": "America/Bogota",  # (GMT-5:00) Bogota, Lima,Quito
        "12": "America/New_York",  # (GMT-5:00) Eastern Time (US & Canada)
        "13": "America/Indianapolis",  # (GMT-5:00) Indiana (East)
        "74": "America/Caracas",  # (GMT-4:00) Caracas
        "14": "America/Halifax",  # (GMT-4:00) Atlantic Time (Canada)
        "77": "Etc/GMT+4",  # (GMT-4:00) Georgetown
        "15": "America/La_Paz",  # (GMT-4:00) La Paz
        "87": "America/Asuncion",  # (GMT-4:00) Paraguay
        "16": "America/Santiago",  # (GMT-3:00) Santiago
        "17": "America/St_Johns",  # (GMT-3:30) Newfoundland
        "18": "America/Sao_Paulo",  # (GMT-3:00) Brasilia
        "19": "America/Buenos_Aires",  # (GMT-3:00) Buenos Aires
        "20": "America/Godthab",  # (GMT-3:00) Nuuk (Greenland)
        "75": "America/Montevideo",  # (GMT-3:00) Uruguay
        "21": "Etc/GMT+2",  # (GMT-2:00) Mid-Atlantic
        "22": "Atlantic/Azores",  # (GMT-1:00) Azores
        "23": "Atlantic/Cape_Verde",  # (GMT-1:00) Cape Verde Is.
        "24": "Atlantic/Reykjavik",  # (GMT) Monrovia
        "80": "Europe/London",  # (GMT) Greenwich Mean Time
        "79": "Africa/Casablanca",  # (GMT) Casablanca
        "25": "Etc/UTC",  # (GMT) Dublin, Edinburgh, Lisbon, London, Canary Is.
        "26": "Europe/Berlin",  # (GMT+1:00) Amsterdam, Berlin, Bern, Rome, Stockholm, Vienna
        "27": "Europe/Budapest",  # (GMT+1:00) Belgrade, Bratislava, Budapest, Ljubljana, Prague
        "28": "Europe/Paris",  # (GMT+1:00) Brussels, Copenhagen, Madrid, Paris
        "78": "Africa/Windhoek",  # (GMT+1:00) Namibia
        "29": "Europe/Warsaw",  # (GMT+1:00) Sarajevo, Skopje, Warsaw, Zagreb
        "30": "Africa/Lagos",  # (GMT+1:00) West Central Africa
        "31": "Europe/Kiev",  # (GMT+2:00) Athens, Sofia, Vilnius
        "32": "Europe/Bucharest",  # (GMT+2:00) Bucharest
        "33": "Africa/Cairo",  # (GMT+2:00) Cairo
        "34": "Africa/Johannesburg",  # (GMT+2:00) Harare, Pretoria
        "35": "Europe/Helsinki",  # (GMT+2:00) Helsinki, Riga, Tallinn
        "36": "Asia/Jerusalem",  # (GMT+2:00) Jerusalem
        "37": "Asia/Baghdad",  # (GMT+3:00) Baghdad
        "38": "Asia/Riyadh",  # (GMT+3:00) Kuwait, Riyadh
        "83": "Europe/Moscow",  # (GMT+3:00) Moscow
        "84": "Europe/Minsk",  # (GMT+3:00) Minsk
        "40": "Africa/Nairobi",  # (GMT+3:00) Nairobi
        "85": "Europe/Istanbul",  # (GMT+3:00) Istanbul
        "41": "Asia/Tehran",  # (GMT+3:30) Tehran
        "42": "Asia/Dubai",  # (GMT+4:00) Abu Dhabi, Muscat
        "43": "Asia/Baku",  # (GMT+4:00) Baku
        "39": "Europe/Volgograd",  # (GMT+3:00) St. Petersburg, Volgograd
        "44": "Asia/Kabul",  # (GMT+4:30) Kabul
        "46": "Asia/Karachi",  # (GMT+5:00) Islamabad, Karachi, Tashkent
        "47": "Asia/Calcutta",  # (GMT+5:30) Kolkata, Chennai, Mumbai, New Delhi
        "51": "Asia/Colombo",  # (GMT+5:30) Sri Jayawardenepara
    }

    return TZ_MAP.get(timezone_num, timezone_num)
