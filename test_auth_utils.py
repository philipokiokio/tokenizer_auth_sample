import unittest
import auth_utils as utils
import uuid


class AccessTokenCases(unittest.TestCase):
    def test_normal_jwt_decode_happy_path(self):
        token_id = uuid.uuid4()
        print(token_id)
        token_data = {"id": str(token_id)}
        jwt_token = utils.create_access_token(data=token_data)

        decoded_token = utils.verify_access_token(token=jwt_token)
        assert decoded_token == token_id

    def test_normal_jwt_decode_sad_path(self):
        token_id = uuid.uuid4()
        token_data = {"id": str(token_id)}
        jwt_token = utils.create_access_token(data=token_data)

        decoded_token = utils.verify_access_token(token=f"{jwt_token}.breaker")

        assert decoded_token != token_id
        assert decoded_token == "jwt token broken"

    def test_top_signed_jwt_decode_happy_path(self):
        token_id = uuid.uuid4()
        token_data = {"id": str(token_id)}
        jwt_token = utils.create_top_level_signed_access_token(data=token_data)

        decoded_token = utils.verify_top_signed_access_token(token=jwt_token)
        assert decoded_token == token_id

    def test_top_signed_jwt_decode_sad_path(self):
        token_id = uuid.uuid4()
        token_data = {"id": str(token_id)}
        jwt_token = utils.create_top_level_signed_access_token(data=token_data)

        decoded_token = utils.verify_top_signed_access_token(
            token=f"{jwt_token}.reader"
        )

        assert decoded_token != token_id
        assert decoded_token == "token broken"

    def test_access_token_flow_happy_path(self):
        token_id = uuid.uuid4()
        token_data = {"id": str(token_id)}
        top_signed_jwt_token = utils.create_top_level_signed_access_token(
            data=token_data
        )

        bare_jwt_token = utils.create_access_token(data=token_data)

        top_signed_token_id = utils.verify_top_signed_access_token(
            token=top_signed_jwt_token
        )
        bare_token_id = utils.verify_access_token(token=bare_jwt_token)

        assert top_signed_token_id == bare_token_id
        assert top_signed_token_id == token_id

    def test_top_signed_token_bare_decode_sad_path(self):
        token_id = uuid.uuid4()
        token_data = {"id": str(token_id)}
        top_signed_jwt_token = utils.create_top_level_signed_access_token(
            data=token_data
        )
        decoded_token_data = utils.verify_access_token(token=top_signed_jwt_token)
        assert decoded_token_data == "jwt token broken"

    def test_black_listed_tokens_path(self):
        token_id = uuid.uuid4()
        token_data = {"id": str(token_id)}
        top_signed_jwt_token = utils.create_top_level_signed_access_token(
            data=token_data
        )

        utils.BLACK_LIST_STORE[top_signed_jwt_token] = top_signed_jwt_token

        bare_jwt_token = utils.create_access_token(data=token_data)
        utils.BLACK_LIST_STORE[bare_jwt_token] = bare_jwt_token

        top_signed_token_id = utils.verify_top_signed_access_token(
            token=top_signed_jwt_token
        )
        bare_token_id = utils.verify_access_token(token=bare_jwt_token)

        assert top_signed_token_id == bare_token_id
        assert top_signed_token_id == "Access Blocked, Token Invalidated"


class RefreshTokenCases(unittest.TestCase):
    def test_normal_jwt_decode_happy_path(self):
        token_id = uuid.uuid4()
        token_data = {"id": str(token_id)}
        jwt_token = utils.create_refresh_token(data=token_data)

        decoded_token = utils.verify_refresh_token(token=jwt_token)
        assert decoded_token == token_id

    def test_normal_jwt_decode_sad_path(self):
        token_id = uuid.uuid4()
        token_data = {"id": str(token_id)}
        jwt_token = utils.create_refresh_token(data=token_data)

        decoded_token = utils.verify_refresh_token(token=f"{jwt_token}.breaker")

        assert decoded_token != token_id
        assert decoded_token == "JWT decrytpion failed"

    def test_top_signed_jwt_decode_happy_path(self):
        token_id = uuid.uuid4()
        token_data = {"id": str(token_id)}
        jwt_token = utils.create_top_level_signed_refresh_token(data=token_data)

        decoded_token = utils.verify_top_signed_refresh_token(token=jwt_token)
        assert decoded_token == token_id

    def test_top_signed_jwt_decode_sad_path(self):
        token_id = uuid.uuid4()
        token_data = {"id": str(token_id)}
        jwt_token = utils.create_top_level_signed_refresh_token(data=token_data)

        decoded_token = utils.verify_top_signed_refresh_token(
            token=f"{jwt_token}.reader"
        )

        assert decoded_token != token_id
        assert decoded_token == "Token broken"

    def test_access_token_flow_happy_path(self):
        token_id = uuid.uuid4()
        token_data = {"id": str(token_id)}
        top_signed_jwt_token = utils.create_top_level_signed_refresh_token(
            data=token_data
        )

        bare_jwt_token = utils.create_refresh_token(data=token_data)

        top_signed_token_id = utils.verify_top_signed_refresh_token(
            token=top_signed_jwt_token
        )
        bare_token_id = utils.verify_refresh_token(token=bare_jwt_token)

        assert top_signed_token_id == bare_token_id
        assert top_signed_token_id == token_id

    def test_top_signed_token_bare_decode_sad_path(self):
        token_id = uuid.uuid4()
        token_data = {"id": str(token_id)}
        top_signed_jwt_token = utils.create_top_level_signed_refresh_token(
            data=token_data
        )
        decoded_token_data = utils.verify_refresh_token(token=top_signed_jwt_token)
        assert decoded_token_data == "JWT decrytpion failed"

    def test_black_listed_tokens_path(self):
        token_id = uuid.uuid4()
        token_data = {"id": str(token_id)}
        top_signed_jwt_token = utils.create_top_level_signed_refresh_token(
            data=token_data
        )

        utils.BLACK_LIST_STORE[top_signed_jwt_token] = top_signed_jwt_token

        bare_jwt_token = utils.create_refresh_token(data=token_data)
        utils.BLACK_LIST_STORE[bare_jwt_token] = bare_jwt_token

        top_signed_token_id = utils.verify_top_signed_refresh_token(
            token=top_signed_jwt_token
        )
        bare_token_id = utils.verify_refresh_token(token=bare_jwt_token)

        assert top_signed_token_id == bare_token_id
        assert top_signed_token_id == "Access Blocked, Token Invalidated"


if __name__ == "__main__":
    unittest.main()
