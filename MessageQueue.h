#ifndef MESSAGE_QUEUE_H
#define MESSAGE_QUEUE_H

typedef struct measure {
  int temperature;
  int humidity;
  int temperatureAlarm = 25;
  int humidityAlarm = 50;
} measure;

class MessageQueue {
private:
  measure *queueArray;
  int capacity;
  int front;
  int rear;
  int count;

public:
  MessageQueue(int size = 100) {
    capacity = size;
    queueArray = new measure[size];
    front = 0;
    rear = -1;
    count = 0;
  }

  ~MessageQueue() {
    delete[] queueArray;
  }

  void enqueue(measure item) {
    if (!isFull()) {
      rear = (rear + 1) % capacity;
      queueArray[rear] = item;
      count++;
    }
  }

  measure dequeue() {
    measure item;
    if (!isEmpty()) {
      item = queueArray[front];
      front = (front + 1) % capacity;
      count--;
    }
    return item;
  }

  measure peek() {
    measure item;
    if (!isEmpty()) {
      item = queueArray[front];
    }
    return item;
  }

  int size() {
    return count;
  }

  bool isEmpty() {
    return (count == 0);
  }

  bool isFull() {
    return (count == capacity);
  }
};

#endif
