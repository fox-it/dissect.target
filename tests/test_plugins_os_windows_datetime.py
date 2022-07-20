import datetime

from dissect.target.plugins.os.windows.datetime import DateTimePlugin


def test_windows_datetime(target_win_tzinfo):
    target_win_tzinfo.add_plugin(DateTimePlugin)

    # Easter Island has a flipped DST to Amsterdam
    assert target_win_tzinfo.datetime.tzinfo.display == "(UTC-06:00) Easter Island"
    assert target_win_tzinfo.datetime.tzinfo.dlt_name == "Easter Island Daylight Time"
    assert target_win_tzinfo.datetime.tzinfo.std_name == "Easter Island Standard Time"
    assert 2019 in target_win_tzinfo.datetime.tzinfo.dynamic_dst

    naive_dt_may = datetime.datetime(2019, 5, 4, 12, 0, 0)
    naive_dt_march = datetime.datetime(2019, 3, 4, 12, 0, 0)

    local_east_st_dt = target_win_tzinfo.datetime.local(naive_dt_may)
    local_east_dt_dt = target_win_tzinfo.datetime.local(naive_dt_march)

    assert local_east_st_dt.tzinfo == target_win_tzinfo.datetime.tzinfo
    assert local_east_dt_dt.tzinfo == target_win_tzinfo.datetime.tzinfo
    assert str(local_east_st_dt) == "2019-05-04 12:00:00-06:00"
    assert str(local_east_dt_dt) == "2019-03-04 12:00:00-05:00"
    assert target_win_tzinfo.datetime.tzinfo.tzname(local_east_st_dt) == "Easter Island Standard Time"
    assert target_win_tzinfo.datetime.tzinfo.tzname(local_east_dt_dt) == "Easter Island Daylight Time"

    utc_east_st_dt = target_win_tzinfo.datetime.to_utc(local_east_st_dt)
    utc_east_dt_dt = target_win_tzinfo.datetime.to_utc(local_east_dt_dt)
    assert utc_east_st_dt == target_win_tzinfo.datetime.to_utc(naive_dt_may)
    assert utc_east_dt_dt == target_win_tzinfo.datetime.to_utc(naive_dt_march)
    assert utc_east_st_dt.tzinfo == datetime.timezone.utc
    assert utc_east_dt_dt.tzinfo == datetime.timezone.utc
    assert str(utc_east_st_dt) == "2019-05-04 18:00:00+00:00"
    assert str(utc_east_dt_dt) == "2019-03-04 17:00:00+00:00"

    eu_tzinfo = target_win_tzinfo.datetime.tz("W. Europe Standard Time")
    local_eu_st_dt = naive_dt_march.replace(tzinfo=eu_tzinfo)
    local_eu_dt_dt = naive_dt_may.replace(tzinfo=eu_tzinfo)
    assert str(local_eu_st_dt) == "2019-03-04 12:00:00+01:00"
    assert str(local_eu_dt_dt) == "2019-05-04 12:00:00+02:00"
    assert eu_tzinfo.tzname(local_eu_st_dt) == "W. Europe Standard Time"
    assert eu_tzinfo.tzname(local_eu_dt_dt) == "W. Europe Daylight Time"

    utc_eu_st_dt = local_eu_st_dt.astimezone(datetime.timezone.utc)
    utc_eu_dt_dt = local_eu_dt_dt.astimezone(datetime.timezone.utc)
    assert str(utc_eu_st_dt) == "2019-03-04 11:00:00+00:00"
    assert str(utc_eu_dt_dt) == "2019-05-04 10:00:00+00:00"

    # Test the switch moment to DST
    assert not eu_tzinfo.is_dst(datetime.datetime(2022, 3, 27, 2, 0, 0, tzinfo=eu_tzinfo))
    assert eu_tzinfo.is_dst(datetime.datetime(2022, 3, 27, 3, 0, 0, tzinfo=eu_tzinfo))
