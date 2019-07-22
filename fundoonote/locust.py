from locust import HttpLocust, TaskSet, task


class UserActions(TaskSet):

    def on_start(self):
        self.login()

    def login(self):
        # login to the application
        response = self.client.get('/fundoonote/user_login/')
        self.client.post('/fundoonote/user_login/', {'username': 'username', 'password': 'password'},)


class ApplicationUser(HttpLocust):
    task_set = UserActions
    min_wait = 0
    max_wait = 0