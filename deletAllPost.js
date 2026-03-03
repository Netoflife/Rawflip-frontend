// Import your Post model
const mongoose = require('mongoose');
const Post = require('./models/Post'); // adjust path to your Post model

// Connect to MongoDB
mongoose.connect('your_mongo_URI_here', {
	  useNewUrlParser: true,
	    useUnifiedTopology: true,
	    })
	    .then(() => {
	    	    console.log('MongoDB connected');
	    	        return deleteAllPosts();
	    	        })
	    	        .catch(err => console.error(err));

	    	        // Function to delete all posts
	    	        async function deleteAllPosts() {
	    	        	    try {
	    	        	    	        const result = await Post.deleteMany({});
	    	        	    	                console.log(`Deleted ${result.deletedCount} posts from the database.`);
	    	        	    	                        process.exit(0);
	    	        	    	                            } catch (err) {
	    	        	    	                            	        console.error('Error deleting posts:', err);
	    	        	    	                            	                process.exit(1);
	    	        	    	                            	                    }
	    	        	    	                            	                    }
	    	        	    	                            }
	    	        	    }
	    	        }
	    })
})
