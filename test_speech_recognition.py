import speech_recognition as sr

# Initialize recognizer
recognizer = sr.Recognizer()

# Load the audio file
audio_file = "uploads/test_file.wav"

# Use AudioFile to read the audio file
with sr.AudioFile(audio_file) as source:
    print("Listening to the audio file...")
    audio = recognizer.record(source)  # Record the entire audio file
    
    try:
        # Recognize speech using CMU Sphinx (Offline method)
        print("You said: " + recognizer.recognize_sphinx(audio))
    except sr.UnknownValueError:
        print("Sorry, I could not understand the audio.")
    except sr.RequestError:
        print("Sphinx is not available.")
