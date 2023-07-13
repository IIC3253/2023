def pytest_addoption(parser):
    parser.addoption("--name", action="store")
    parser.addoption("--path", action="store")
