/*
 * SPDX-FileCopyrightText: NVIDIA CORPORATION & AFFILIATES
 * Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: GPL-2.0-only or BSD-2-Clause
 */

#include <gtest/gtest.h>

#include <pthread.h>
#include <mutex>
#include "core/event/job_queue.h"

// Simple test job structure
struct test_job {
    int id;
    int priority;
};

typedef job_queue<test_job> job_queue_t;

class job_queue_test : public ::testing::Test {
public:
    job_queue_t queue;

protected:
    void SetUp() override {
        // Clear queue before each test
        auto jobs = queue.get_all();
        jobs.clear();
    }
};


/**
 * @test job_queue_test.ti_1
 * @brief
 * Test single job insert and retreival.
 * @details
 *    Test job_queue<T>::insert_job(const T &job) function insert a job with const object.
 */

TEST_F(job_queue_test, ti_1) {
    const test_job job{1, 10};
    queue.insert_job(job);
    EXPECT_EQ(queue.get_all().size(), 1UL);
    
    auto &jobs = queue.get_all();
    EXPECT_EQ(jobs[0].id, 1);
    EXPECT_EQ(jobs[0].priority, 10);
}

/**
 * @test job_queue_test.ti_2
 * @brief
 *    Test job queue insert -> get_all interleaved pattern.
 * @details
 */
TEST_F(job_queue_test, ti_2) {
    const test_job job1{1, 20};
    int redo=10;
    while (redo--) {
        queue.insert_job(job1);
        auto &jobs = queue.get_all();
        EXPECT_EQ(jobs.size(), 1UL);
        jobs.clear();
    }
}

/**
 * @test job_queue_test.ti_3
 * @brief
 *    Test job queue insert a batch (X) and the next get_all will get all the jobs.
 * @details
 */
TEST_F(job_queue_test, ti_3) {
    const test_job job1{1, 20};
    int x=100;
    while (x--) {
        queue.insert_job(job1);
    }
    auto &jobs = queue.get_all();
    EXPECT_EQ(jobs.size(), 100UL);
    jobs.clear();
}

/**
 * @test job_queue_test.ti_4
 * @brief
 *    Test get_all() on empty queue returns empty vector.
 * @details
 */
TEST_F(job_queue_test, ti_4) {
    auto jobs = queue.get_all();
    EXPECT_EQ(jobs.size(), 0UL);
    EXPECT_TRUE(jobs.empty());
}

/**
 * @test job_queue_test.ti_5
 * @brief
 *    Test that jobs maintain insertion order (FIFO).
 * @details
 */
TEST_F(job_queue_test, ti_5) {
    std::vector<test_job> inserted_jobs = {
        {100, 1}, {200, 2}, {300, 3}, {400, 4}, {500, 5}
    };
    
    for (const auto& job : inserted_jobs) {
        queue.insert_job(job);
    }
    
    auto& jobs = queue.get_all();
    EXPECT_EQ(jobs.size(), inserted_jobs.size());
    
    for (size_t i = 0; i < jobs.size(); ++i) {
        EXPECT_EQ(jobs[i].id, inserted_jobs[i].id);
        EXPECT_EQ(jobs[i].priority, inserted_jobs[i].priority);
    }
    
    jobs.clear();
}

/**
 * @test job_queue_test.ti_6
 * @brief
 *    Test concurrent access with multiple producer threads and single consumer.
 * @details
 *    Validates thread-safety of job_queue with multiple threads inserting jobs
 *    concurrently while a single consumer thread retrieves them.
 */
TEST_F(job_queue_test, ti_6) {
    const int num_producer_threads = 4;
    const int jobs_per_thread = 250;
    const int total_jobs = num_producer_threads * jobs_per_thread;
    
    std::vector<pthread_t> producer_threads(num_producer_threads);
    std::atomic<int> jobs_consumed(0);
    std::atomic<bool> stop_consumer(false);

    // Producer thread function
    struct producer_data {
        job_queue_t* queue;
        int thread_id;
        int jobs_count;
    };
    
    auto producer_func = [](void* arg) -> void* {
        producer_data* data = static_cast<producer_data*>(arg);
        
        for (int i = 0; i < data->jobs_count; ++i) {
            test_job job{data->thread_id * 1000 + i, data->thread_id};
            data->queue->insert_job(job);
        }
        return nullptr;
    };
    
    // Consumer thread function
    pthread_t consumer_thread;
    struct consumer_data {
        job_queue_t* queue;
        std::atomic<int>* jobs_consumed;
        std::atomic<bool>* stop_flag;
    };
    
    consumer_data c_data{&queue, &jobs_consumed, &stop_consumer};
    
    auto consumer_func = [](void* arg) -> void* {
        consumer_data* data = static_cast<consumer_data*>(arg);
        
        while (!data->stop_flag->load()) {
            auto& jobs = data->queue->get_all();
            data->jobs_consumed->fetch_add(jobs.size());
            jobs.clear();
            usleep(5000);
        }
        
        // Final consumption after stop signal
        auto& jobs = data->queue->get_all();
        data->jobs_consumed->fetch_add(jobs.size());
        jobs.clear();
        
        return nullptr;
    };
    
    // Start consumer thread
    ASSERT_EQ(0, pthread_create(&consumer_thread, nullptr, consumer_func, &c_data));
    
    // Start producer threads
    std::vector<producer_data> p_data(num_producer_threads);
    for (int i = 0; i < num_producer_threads; ++i) {
        p_data[i] = {&queue, i, jobs_per_thread};
        ASSERT_EQ(0, pthread_create(&producer_threads[i], nullptr, producer_func, &p_data[i]));
    }
    
    // Wait for all producer threads to complete
    for (int i = 0; i < num_producer_threads; ++i) {
        ASSERT_EQ(0, pthread_join(producer_threads[i], nullptr));
    }
    
    // Give consumer some time to process remaining jobs
    usleep(50000);
    
    // Stop consumer
    stop_consumer.store(true);
    ASSERT_EQ(0, pthread_join(consumer_thread, nullptr));
    
    // Verify all jobs were consumed
    EXPECT_EQ(jobs_consumed.load(), total_jobs);
    
    // Verify queue is empty
    auto& remaining_jobs = queue.get_all();
    EXPECT_EQ(remaining_jobs.size(), 0UL);
}
