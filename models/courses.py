class Course:
    def __init__(self):
        self.courses = []

    def add_course(self, course_name):
        self.courses.append(course_name)

    def get_courses(self):
        return self.courses

courses_db = Course()
