def grade(tests) -> int:
    """
    :param tests: the results of all the tests
    :return: the lowest grade in the tests
    """
    # TODO: this needs a ton of fleshing out
    return max([tests[test]['max_grade'] for test in tests])
