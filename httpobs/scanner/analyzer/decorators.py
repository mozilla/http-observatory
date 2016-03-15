from functools import wraps

from httpobs.scanner.grader import get_score_modifier


def scored_test(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        test_result = func(*args, **kwargs)
        test_result['name'] = func.__name__.replace('_', '-')  # add the test name
        test_result['score_modifier'] = get_score_modifier(test_result['result'])  # and its score modifier

        return test_result

    return wrapper
