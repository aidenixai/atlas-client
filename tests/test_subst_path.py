"""_subst_path: substitutes {key} into URL path segments.

Guards that a placeholder name may contain a hyphen, dot or colon
(`{sub-id}`, `{api.v}`, `{ns:id}`): a plain `\\w+` used to break such names and leave the token
as a literal, giving a 4xx. Values are url-encoded; unresolved tokens stay as they are.
"""
from aidenix_atlas._recipe_runtime import _subst_path


def test_plain_word_param():
    url, consumed = _subst_path("https://api.x/v1/{id}/full", {"id": "abc"})
    assert url == "https://api.x/v1/abc/full"
    assert consumed == {"id"}


def test_hyphenated_param_name():
    url, consumed = _subst_path("https://api.x/{sub-id}/data", {"sub-id": "42"})
    assert url == "https://api.x/42/data"
    assert consumed == {"sub-id"}


def test_dotted_and_colon_param_names():
    url, consumed = _subst_path("https://api.x/{api.v}/{ns:id}", {"api.v": "2", "ns:id": "z"})
    assert url == "https://api.x/2/z"
    assert consumed == {"api.v", "ns:id"}


def test_value_is_url_encoded():
    url, consumed = _subst_path("https://api.x/{q}", {"q": "a/b c"})
    assert url == "https://api.x/a%2Fb%20c"
    assert consumed == {"q"}


def test_unresolved_token_left_literal():
    url, consumed = _subst_path("https://api.x/{id}", {})
    assert url == "https://api.x/{id}"
    assert consumed == set()


def test_empty_value_not_consumed():
    url, consumed = _subst_path("https://api.x/{id}", {"id": ""})
    assert url == "https://api.x/{id}"
    assert consumed == set()
