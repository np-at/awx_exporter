from unittest import TestCase

from awx_exporter import utils

sample_dict = {
    "testing": 1,
    "testing2": 3,
    "testing3": {
        1: 2,
        2: [1, 2, 3, 4, 5],
        3: {
            "testing": "testing"
        }
    }

}


class Test(TestCase):
    def test_recurse_dict(self):
        expected_output_skip_invalid = {'testing': 1, 'testing2': 3, 'testing3': {}}
        expected_output_replace_invalid = {'testing': 1, 'testing2': 3, 'testing3': {'invalid_group_name_9170': 2,
                                                                                     'invalid_group_name_5051': [1, 2,
                                                                                                                 3, 4,
                                                                                                                 5],
                                                                                     'invalid_group_name_6717': {
                                                                                         'testing': 'testing'}}}
        skip_inval = utils.recurse_dict(sample_dict,
                                        func=lambda x, y, c=True: utils.check_group_name_compatibility(x, y, c))
        replace_invalid = utils.recurse_dict(sample_dict,
                                             func=lambda x, y, c=False: utils.check_group_name_compatibility(x,
                                                                                                             y,
                                                                                                             c,
                                                                                                             ))
        self.assertDictEqual(expected_output_skip_invalid, skip_inval)
    # TODO: implement testing for random number portion of function
    # self.assertDictEqual(expected_output_replace_invalid, replace_invalid)


class Test1(TestCase):
    def test_output_to_file(self):
        self.assertTrue(True)
