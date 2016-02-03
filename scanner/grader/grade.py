import database

grade_order = ['A+', 'A', 'A-', 'B+', 'B', 'B-', 'C+', 'C', 'C-', 'F']
output = {
        'grade': 'A+',
        'grade_reasons': {}
}


def __set_grade(grade: str, test: str, reason=None) -> str:
    """
    Updates the grade, but only if it's worse than the current grade

    :param grade: the new maximum grade
    :return: the current grade after possible updating
    """
    if grade_order.index(grade) > grade_order.index(output['grade']):
        output['grade'] = grade

    if reason:
        reason += ' Grade capped at {grade}.'.format(grade=grade)
        output['grade_reasons'][test] = reason

    return output['grade']


def grade(scan_id: int) -> dict:
    # Get the test results from the database
    test_results = database.select_test_results(scan_id)

    # TODO: this needs a ton of fleshing out

    # Grade the CSP stuff
    test = 'content-security-policy'
    result = test_results[test]['result']

    if result == 'csp-implemented-with-no-unsafe':
        pass
    elif result == 'csp-implemented-with-unsafe-allowed-in-style-src-only':
        __set_grade('A', test, 'CSP implemented with unsafe-inline in style-src.')
    else:
        __set_grade('B', test, 'CSP not implemented or implemented improperly.')

    # Grade the TLS stuff
    test = 'tls-configuration'
    result = test_results[test]['result']

    if result == 'old-tls-configuration':
        __set_grade('C', test, 'TLS configuration uses the Mozilla old configuration.')
    elif result == 'bad-tls-configuration':
        __set_grade('F', test, 'TLS configuration doesn\'t match any known good Mozilla configurations.')

    return database.insert_scan_grade(scan_id, output)
