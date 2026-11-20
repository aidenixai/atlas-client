"""_dig: dotted path plus `[]` list expansion (ArcGIS/GeoJSON nested data → flat records).

Guards that a nested source (ArcGIS FeatureServer `features[].attributes`,
GeoJSON `features[].properties`) yields the same flat records as Socrata, with no special code
in the executor. `_dig` is embedded into client recipes via getsource, so its behaviour must stay stable.
"""
from aidenix_atlas._recipe_runtime import _dig


def test_empty_path_returns_whole_object():
    assert _dig({"a": 1}, "") == {"a": 1}


def test_plain_dotted_path_unchanged():
    assert _dig({"message": {"items": [1, 2]}}, "message.items") == [1, 2]
    assert _dig({"a": {"b": {"c": 7}}}, "a.b.c") == 7


def test_missing_key_returns_none():
    assert _dig({"a": 1}, "a.b") is None
    assert _dig({"a": 1}, "x") is None


def test_non_dict_midpath_returns_none():
    assert _dig({"a": [1, 2]}, "a.b") is None


def test_arcgis_features_attributes():
    payload = {"features": [{"attributes": {"AIN": "1"}, "geometry": {}},
                            {"attributes": {"AIN": "2"}, "geometry": {}}]}
    assert _dig(payload, "features[].attributes") == [{"AIN": "1"}, {"AIN": "2"}]


def test_geojson_features_properties():
    payload = {"type": "FeatureCollection",
               "features": [{"properties": {"id": 10}}, {"properties": {"id": 11}}]}
    assert _dig(payload, "features[].properties") == [{"id": 10}, {"id": 11}]


def test_bare_wildcard_returns_list_as_is():
    payload = {"features": [{"attributes": {"x": 1}}]}
    assert _dig(payload, "features[]") == [{"attributes": {"x": 1}}]


def test_toplevel_wildcard_on_list():
    assert _dig([{"a": 1}, {"a": 2}], "[]") == [{"a": 1}, {"a": 2}]


def test_wildcard_on_nonlist_returns_none():
    assert _dig({"features": {"not": "a list"}}, "features[].attributes") is None


def test_wildcard_missing_leaf_yields_none_per_element():
    payload = {"features": [{"attributes": {"AIN": "1"}}, {"other": {}}]}
    assert _dig(payload, "features[].attributes") == [{"AIN": "1"}, None]


def test_nested_wildcard_chain():
    payload = {"data": {"features": [{"attributes": {"v": 1}}, {"attributes": {"v": 2}}]}}
    assert _dig(payload, "data.features[].attributes") == [{"v": 1}, {"v": 2}]
