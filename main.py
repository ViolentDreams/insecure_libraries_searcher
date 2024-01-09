from abc import ABC, abstractmethod
import re
import requests


class GitClient(ABC):
    URL_PATTERN: str

    def __init__(self, repo_url):
        self.repo_url = repo_url
        self.requirements_list = self.get_requirements_list()

    @abstractmethod
    def _get_file_content(self, files_urls):
        pass

    @abstractmethod
    def _get_repo_api_url(self):
        pass

    @abstractmethod
    def _search_requirements_files(self, repo_api_url):
        pass

    @abstractmethod
    def get_requirements_list(self):
        pass


class GithubClient(GitClient):
    URL_PATTERN = r'(?:https?://)?github.com/([^/]+)/([^/]+)'

    def _get_repo_api_url(self):
        matches = re.search(self.URL_PATTERN, self.repo_url)

        if matches:
            user_repo = f'{matches.group(1)}/{matches.group(2)}'
            return requests.get(url='https://api.github.com/repos/' + user_repo + '/contents/')

    def _search_requirements_files(self, repo_api_url):
        for repo_content in repo_api_url.json():
            if 'requirements' in repo_content['name'] and repo_content['type'] == 'file':
                return [repo_content['download_url']]
            elif 'requirements' in repo_content['name'] and repo_content['type'] == 'dir':
                dir_api_url = requests.get(url=repo_content['url'])
                files = []
                for dir_content in dir_api_url.json():
                    if '.txt' in dir_content['name']:
                        files.append(dir_content['download_url'])
                return files

    def _get_file_content(self, files_urls):
        content = []
        for file_url in files_urls:
            result = requests.get(file_url).text.split(sep='\n')
            while '' in result:
                result.remove('')
            content.extend(result)
        return content

    def get_requirements_list(self):
        repo_api_url = self._get_repo_api_url()
        requirement_files = self._search_requirements_files(repo_api_url=repo_api_url)
        requirement_files_content = self._get_file_content(files_urls=requirement_files)
        return requirement_files_content


class Package:

    def __init__(self, name, delimeter, version):
        self.name = name
        self.delimeter = delimeter
        self.version = version

    def __str__(self):
        return f'{self.name} {self.delimeter} {self.version}'

    def __eq__(self, other):
        if self.delimeter == '==':

            if other.delimeter == '>=':
                return self.version >= other.version
            elif other.delimeter == '>':
                return self.version > other.version
            elif other.delimeter == '<=':
                return self.version <= other.version
            elif other.delimeter == '<':
                return self.version < other.version

        else:

            if (other.delimeter == '>=' or other.delimeter == '>') and (
                    self.delimeter == '>=' or self.delimeter == '>'):
                return True
            if (other.delimeter == '<=' or other.delimeter == '<') and (
                    self.delimeter == '<=' or self.delimeter == '<'):
                return True

            if other.delimeter == '<=' and self.delimeter == '>=':
                return self.version <= other.version
            if other.delimeter == '>=' and self.delimeter == '<=':
                return self.version >= other.version

            if (other.delimeter == '<' or other.delimeter == '<=') and self.delimeter == '>':
                return self.version < other.version
            if (other.delimeter == '>' or other.delimeter == '>=') and self.delimeter == '<':
                return self.version > other.version

            if other.delimeter == '<' and (self.delimeter == '>=' or self.delimeter == '>'):
                return self.version < other.version
            if other.delimeter == '>' and (self.delimeter == '<=' or self.delimeter == '<'):
                return self.version > other.version


class PackageInsecureLimits(Package):

    def __init__(self, name, delimeter_first_requirement, version_first_requirement,
                 delimeter_second_requirement='>', version_second_requirement='0'):
        self.name = name
        self.first_requirement = Package(name=name, delimeter=delimeter_first_requirement,
                                         version=version_first_requirement)
        self.second_requirement = Package(name=name, delimeter=delimeter_second_requirement,
                                          version=version_second_requirement)

    def __eq__(self, other):
        if other == self.first_requirement:
            if other == self.second_requirement:
                return True

        return False

    def __str__(self):
        return (f'{self.first_requirement} and '
                f'{self.second_requirement}')


class VulnerabilityPackage(Package):
    INSECURE_SPECS_PATTERN = r'([<>=!]+)\s*(\d+(\.\d+)*)'

    def __init__(self, name, advisory, specs):
        self.name = name
        self.advisory = advisory
        self.version_limits = []
        self._version_limits(specs=specs)

    def __eq__(self, other):
        for limit in self.version_limits:
            if limit == other:
                return True

    def _version_limits(self, specs):
        for spec in specs:
            spec = spec.split(sep=',')
            args = [self.name]
            for version in spec:
                matches = re.match(self.INSECURE_SPECS_PATTERN, version)
                args.append(matches.group(1))
                args.append(matches.group(2))
            self.version_limits.append(PackageInsecureLimits(*args))


class InsecureLibraryPackage(Package):

    def __init__(self, name):
        self.name = name
        self.vulnerabilities = []

    def _add_vulnerability(self, advisory, specs):
        self.vulnerabilities.append(VulnerabilityPackage(name=self.name, advisory=advisory, specs=specs))

    def match_vulnerability(self, package):
        if package.name == self.name:
            result = []
            for vulnerability in self.vulnerabilities:
                if vulnerability == package:
                    result.append(vulnerability)
            if result:
                return result


class PackagesSource:
    LIB_STRING_PATTERN = r'([\w\s\W]+?)\s*([<>=!]+)\s*(\d+(\.\d+)*)'

    def __init__(self, client):
        self.client = client

    def get_libraries(self):
        file_contents = self.client.requirements_list
        libraries = []

        for lib_string in file_contents:
            matches = re.match(self.LIB_STRING_PATTERN, lib_string)
            if matches:
                name = matches.group(1)
                delimeter = matches.group(2)
                version = matches.group(3)
            else:
                name = lib_string
                delimeter = '>'
                version = '0'
            libraries.append(Package(name=name, delimeter=delimeter, version=version))

        return libraries


class PackagesInsecureSource:
    LIB_STRING_PATTERN = r'^([\w\s\W]+?)(?:\s*([<>=!]+)\s*(\d+(\.\d+)*))?$'
    INSECURE_FULL = requests.get(
        url='https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json').json()

    def __init__(self, client):
        self.client = client

    def get_libraries(self):
        file_contents = self.client.requirements_list
        result = []

        for lib_string in file_contents:
            matches = re.match(self.LIB_STRING_PATTERN, lib_string)
            name = matches.group(1)
            if name in self.INSECURE_FULL or name.lower() in self.INSECURE_FULL:
                if name.lower() in self.INSECURE_FULL:
                    name = name.lower()
                insecure_package = InsecureLibraryPackage(name=name)
                for vulnerability in self.INSECURE_FULL[name]:
                    insecure_package._add_vulnerability(advisory=vulnerability['advisory'],
                                                        specs=vulnerability['specs'])
                result.append(insecure_package)
        if result:
            return result


client = GithubClient(repo_url='https://github.com/PyGithub/PyGithub/tree/main')
source = PackagesSource(client=client)
requirement_libraries = source.get_libraries()
insecurity_source = PackagesInsecureSource(client=client)
insecurity_libraries = insecurity_source.get_libraries()
for insecure_library in insecurity_libraries:
    for requirement_library in requirement_libraries:
        vulnerability_packages = insecure_library.match_vulnerability(package=requirement_library)
        if vulnerability_packages:
            for package in vulnerability_packages:
                print(package.advisory)
                