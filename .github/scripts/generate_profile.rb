#!/usr/bin/env ruby
# frozen_string_literal: true

require 'erb'
require 'json'
require 'time'

LIFE_JSON_PATH = File.join(__dir__, '..', '..', 'life.json')
README_PATH = File.join(__dir__, '..', '..', 'README.md')
TEMPLATE_PATH = File.join(__dir__, '..', 'templates', 'README.md.erb')

def load_life_data
  JSON.parse(File.read(LIFE_JSON_PATH))
end

def find_most_recent_date(data)
  data.keys
      .reject { |k| k == 'version' }
      .max_by { |date_str| Date.parse(date_str) }
end

def format_time(iso_time)
  return nil if iso_time.nil? || iso_time.to_s.empty?

  time = Time.parse(iso_time)
  hour = time.hour % 12
  hour = 12 if hour.zero?
  minute = time.min.to_s.rjust(2, '0')
  period = time.hour >= 12 ? 'pm' : 'am'
  "#{hour}:#{minute}#{period}"
end

def format_duolingo_lessons(lessons)
  return nil if lessons.nil? || lessons.empty?

  parts = lessons.map { |lang, count| "#{count} #{lang} lesson#{count == 1 ? '' : 's'}" }
  parts.join(' and ')
end

def join_naturally(items)
  case items.length
  when 0 then nil
  when 1 then items[0]
  when 2 then "#{items[0]} and #{items[1]}"
  else "#{items[0..-2].join(', ')}, and #{items[-1]}"
  end
end

def generate_dynamic_content(entry)
  sentences = []

  # Sleep sentence
  bedtime = format_time(entry['bedtime'])
  waketime = format_time(entry['waketime'])

  sleep_parts = []
  sleep_parts << (bedtime ? "Last night I went to bed at #{bedtime}" : "I haven't yet recorded my bedtime from last night")
  sleep_parts << (waketime ? "today I got up at #{waketime}" : "today I have not gotten up yet")
  sentences << "#{sleep_parts[0]}, and #{sleep_parts[1]}."

  # Activities sentence (calories, exercise, Duolingo)
  activities = []
  calories = entry['calories_eaten']
  exercise = entry['exercise_minutes']
  duolingo = format_duolingo_lessons(entry['duolingo_lessons'])

  activities << "eaten #{calories.to_i} calories" if calories && calories > 0
  activities << "worked out for #{exercise.round} minutes" if exercise && exercise > 0
  activities << "done #{duolingo} on Duolingo" if duolingo

  if activities.any? && duolingo
    sentences << "I've #{join_naturally(activities)}."
  elsif activities.any?
    sentences << "I've #{join_naturally(activities)}, but haven't done any Duolingo lessons yet today."
  else
    sentences << "I haven't eaten anything, worked out, or done any Duolingo lessons yet today."
  end

  # Tasks sentence
  tasks = entry['percent_tasks_completed']
  if tasks.nil? || tasks.zero?
    sentences << "I haven't completed any tasks on my todo list yet."
  elsif tasks == 100
    sentences << "I've completed all the tasks on my todo list for the day!"
  else
    sentences << "I have completed #{tasks}% of my todo list for the day."
  end

  sentences.join(' ')
end

def generate_readme(dynamic_content)
  template = File.read(TEMPLATE_PATH)
  content = dynamic_content
  ERB.new(template).result(binding)
end

def main
  data = load_life_data
  most_recent_date = find_most_recent_date(data)

  if most_recent_date.nil?
    puts 'No date entries found in life.json'
    exit 1
  end

  puts "Most recent date: #{most_recent_date}"

  entry = data[most_recent_date]
  dynamic_content = generate_dynamic_content(entry)
  readme_content = generate_readme(dynamic_content)

  File.write(README_PATH, readme_content)
  puts 'README.md updated successfully!'
  puts
  puts readme_content
end

main
