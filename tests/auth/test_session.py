import unittest
import msiempy


class T(unittest.TestCase):
    def test(self):

        session = msiempy.NitroSession()
        session.login()

        print(str(session.__dict__))

        print("ESM build : " + str(session.request("build_stamp")))

        tz = session.request("time_zones")
        for t in tz:
            if not "offset" in t:
                self.fail(
                    "Timezone object from the SIEM doesn't represent a offset attribute"
                )

    def test_invalid_session(self):
        session = msiempy.NitroSession()
        session.login()
        session.session.headers["X-Xsrf-Token"] = session.session.headers[
            "X-Xsrf-Token"
        ] + str(
            "abc"
        )  # corrupt the token
        print("ESM build : " + str(session.request("build_stamp")))
        session.session.headers["Cookie"] = session.session.headers["Cookie"] + str(
            "abc"
        )  # corrupt the cokie
        print("ESM build : " + str(session.request("build_stamp")))
        session.logout()
        session.login()
        session.session.headers["X-Xsrf-Token"] = session.session.headers[
            "X-Xsrf-Token"
        ] + str(
            "abc"
        )  # corrupt the token
        print("ESM build : " + str(session.request("build_stamp")))
        session.session.headers["Cookie"] = session.session.headers["Cookie"] + str(
            "abc"
        )  # corrupt the cokie
        print("ESM build : " + str(session.request("build_stamp")))
