from datetime import datetime


class AnalysisTask:
    """分析任务管理类（独立模块，便于测试）"""

    def __init__(self):
        self.tasks = {}
        self.task_counter = 0

    def create_task(self, file_path):
        """创建新任务"""
        self.task_counter += 1
        task_id = f"task_{self.task_counter:04d}"

        task = {
            'id': task_id,
            'file_path': file_path,
            'status': 'pending',
            'results': None,
            'created_at': datetime.now().isoformat()
        }

        self.tasks[task_id] = task
        return task_id

    def update_task(self, task_id, status, results=None):
        """更新任务状态"""
        if task_id in self.tasks:
            self.tasks[task_id]['status'] = status
            if results:
                self.tasks[task_id]['results'] = results
            self.tasks[task_id]['updated_at'] = datetime.now().isoformat()

    def get_task(self, task_id):
        """获取任务信息"""
        return self.tasks.get(task_id)
