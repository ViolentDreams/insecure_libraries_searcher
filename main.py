from abc import ABC, abstractmethod
import re
import requests


class GitClient(ABC):
    """
    Abstract class template for classes to work with different git repositories
    Describes methods for parsing the list of required libraries for a project in the repository
    """

    URL_PATTERN: str
    API_URL_TEMPLATE: str

    def __init__(self, repo_url: str) -> None:
        self.repo_url = repo_url
        self.requirements_list = self.get_requirements_list()

    @abstractmethod
    def _get_files_content(self, files_urls: list) -> list[str]:
        pass

    @abstractmethod
    def _get_repo_api_url(self) -> str:
        pass

    @abstractmethod
    def _search_requirements_files(self, repo_api_request: requests.models.Response) -> list[str]:
        pass

    @abstractmethod
    def get_requirements_list(self) -> list:
        pass


class GithubClient(GitClient):
    URL_PATTERN = r'(?:https?://)?github.com/([^/]+)/([^/]+)'
    API_URL_TEMPLATE = 'https://api.github.com/repos/'

    def _get_repo_api_url(self):
        matches = re.search(self.URL_PATTERN, self.repo_url)

        if matches:
            user_repo = f'{matches.group(1)}/{matches.group(2)}'
            repo_api_url = self.API_URL_TEMPLATE + user_repo + '/contents/'
            return repo_api_url

    def _search_requirements_files(self, repo_api_request):
        files = []
        for repo_content in repo_api_request.json():
            if 'requirements' in repo_content['name'] and repo_content['type'] == 'file':
                files.append(repo_content['download_url'])

            elif 'requirements' in repo_content['name'] and repo_content['type'] == 'dir':
                dir_api_url = requests.get(url=repo_content['url'])
                for dir_content in dir_api_url.json():
                    if '.txt' in dir_content['name']:
                        files.append(dir_content['download_url'])
        return files

    def _get_files_content(self, files_urls):
        content = []
        for file_url in files_urls:
            file_data = requests.get(file_url).text
            result = file_data.split(sep='\n')
            while '' in result:
                result.remove('')
            content.extend(result)
        return content

    def get_requirements_list(self):
        repo_api_url = self._get_repo_api_url()
        repo_api_request = requests.get(url=repo_api_url)

        requirement_files = self._search_requirements_files(repo_api_request=repo_api_request)
        requirement_files_content = self._get_files_content(files_urls=requirement_files)

        source = PackagesSource()
        requirement_libraries = source.get_libraries(libs_str_list=requirement_files_content)

        return requirement_libraries


class LibraryPackage:
    """
    A class that packages the library name and its version requirements into a single object
    The class also overrides the method for comparing its objects, considering the comparison mark and the version
    """

    def __init__(self, name, delimeter, version):
        self.name = name
        self.delimeter = delimeter
        self.version = version

    def __str__(self):
        return f'{self.name} {self.delimeter} {self.version}'

    def __contains__(self, item):
        if self.delimeter == '==':

            if item.delimeter == '>=':
                return self.version >= item.version
            elif item.delimeter == '>':
                return self.version > item.version
            elif item.delimeter == '<=':
                return self.version <= item.version
            elif item.delimeter == '<':
                return self.version < item.version

        else:

            if (item.delimeter == '>=' or item.delimeter == '>') and (
                    self.delimeter == '>=' or self.delimeter == '>'):
                return True
            if (item.delimeter == '<=' or item.delimeter == '<') and (
                    self.delimeter == '<=' or self.delimeter == '<'):
                return True

            if item.delimeter == '<=' and self.delimeter == '>=':
                return self.version <= item.version
            if item.delimeter == '>=' and self.delimeter == '<=':
                return self.version >= item.version

            if (item.delimeter == '<' or item.delimeter == '<=') and self.delimeter == '>':
                return self.version < item.version
            if (item.delimeter == '>' or item.delimeter == '>=') and self.delimeter == '<':
                return self.version > item.version

            if item.delimeter == '<' and (self.delimeter == '>=' or self.delimeter == '>'):
                return self.version < item.version
            if item.delimeter == '>' and (self.delimeter == '<=' or self.delimeter == '<'):
                return self.version > item.version


class Vulnerability:
    """
    A class for storing information about vulnerabilities in InsecureLibrary-class objects.
    Objects contain: the name of the library to which the vulnerability belongs, the description of the vulnerability
    and the scope of versions in which the vulnerability is present
    """

    INSECURE_SPECS_PATTERN = r'([<>=!]+)\s*(\d+(\.\d+)*)'

    def __init__(self, name, advisory, specs):
        self.name = name
        self.advisory = advisory
        self.version_limits = []
        self._get_version_limits(specs=specs)

    def __contains__(self, item):
        for limit in self.version_limits:
            if not (item in limit):
                return
        return True

    def __str__(self):
        return self.advisory

    def _get_version_limits(self, specs):
        for spec in specs:
            spec = spec.split(sep=',')
            kwargs = dict([('name', self.name)])
            for version in spec:
                matches = re.match(self.INSECURE_SPECS_PATTERN, version)
                kwargs['delimeter'] = matches.group(1)
                kwargs['version'] = matches.group(2)
                self.version_limits.append(LibraryPackage(**kwargs))


class InsecureLibrary:
    """
    A class that packages the library name and its vulnerabilities list into a single object
    Has a method to search for vulnerabilities included in the LibraryPackage-class object specified in the argument
    """

    def __init__(self, name):
        self.name = name
        self.vulnerabilities = []

    def add_vulnerability(self, advisory, specs):
        self.vulnerabilities.append(Vulnerability(name=self.name, advisory=advisory, specs=specs))

    def match_vulnerability(self, lib_package):
        if lib_package.name == self.name:
            result = []
            for vulnerability in self.vulnerabilities:
                if lib_package in vulnerability:
                    result.append(vulnerability)
            if result:
                return result


class PackagesSource:
    """
    Source class for creating LibraryPackage-class objects from strings with a library description
    """

    LIB_STRING_PATTERN = r'([\w\s\W]+?)\s*([<>=!]+)\s*(\d+(\.\d+)*)'

    def get_libraries(self, libs_str_list):
        libraries = []

        for lib_string in libs_str_list:
            matches = re.match(self.LIB_STRING_PATTERN, lib_string)
            if matches:
                name = matches.group(1)
                delimeter = matches.group(2)
                version = matches.group(3)
            else:
                name = lib_string
                delimeter = '>'
                version = '0'
            name = name.lower()
            libraries.append(LibraryPackage(name=name, delimeter=delimeter, version=version))

        return libraries


class InsecureLibrariesSource:
    """
    Source class for creating objects that store a list of library vulnerabilities. Takes a list of
    LibraryPackage-class objects as input and outputs a list of InsecureLibrary-class objects with vulnerabilities
    for libraries from the input
    """

    LIB_STRING_PATTERN = r'^([\w\s\W]+?)(?:\s*([<>=!]+)\s*(\d+(\.\d+)*))?$'
    INSECURE_FULL_CATALOGUE = requests.get(
        url='https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json').json()

    def get_libraries(self, requirement_libs_list):
        result = []

        for library in requirement_libs_list:
            name = library.name
            if name in self.INSECURE_FULL_CATALOGUE:
                insecure_package = InsecureLibrary(name=name)
                for vulnerability in self.INSECURE_FULL_CATALOGUE[name]:
                    insecure_package.add_vulnerability(advisory=vulnerability['advisory'],
                                                       specs=vulnerability['specs'])
                result.append(insecure_package)
        if result:
            return result


client = GithubClient(repo_url='https://github.com/PyGithub/PyGithub')

insecurity_source = InsecureLibrariesSource()
insecurity_libraries = insecurity_source.get_libraries(requirement_libs_list=client.requirements_list)

vulnerabilities = []
for insecure_library in insecurity_libraries:
    for requirement_library in client.requirements_list:
        if insecure_library.name == requirement_library.name:
            match = insecure_library.match_vulnerability(lib_package=requirement_library)
            if match:
                vulnerabilities.extend(match)

if vulnerabilities:
    for package in vulnerabilities:
        print(package.advisory, end='')
        print('\n')
